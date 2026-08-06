"""Tests for the DNS wire format and the SPF/DKIM/DMARC parsers."""
import base64
import struct
import subprocess
import unittest

from spoofscan import dkim, dmarc, dns, spf


def txt_rdata(value: str) -> bytes:
    out, raw = b"", value.encode()
    while raw:
        out += bytes([min(255, len(raw))]) + raw[:255]
        raw = raw[255:]
    return out


def response(qname: str, qtype: int, rdatas, rcode: int = 0, ad: bool = False) -> bytes:
    tid = 0x4242
    flags = 0x8180 | (0x0020 if ad else 0) | rcode
    packet = struct.pack(">HHHHHH", tid, flags, 1, len(rdatas), 0, 0)
    packet += dns.encode_name(qname) + struct.pack(">HH", qtype, 1)
    for rdata in rdatas:
        packet += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 300, len(rdata)) + rdata
    return packet


class TestWireFormat(unittest.TestCase):
    def test_txt_record(self):
        packet = response("example.org", dns.TXT, [txt_rdata("v=spf1 -all")])
        answer = dns.parse_response(packet, 0x4242)
        self.assertEqual(answer.records, ["v=spf1 -all"])
        self.assertTrue(answer.ok)

    def test_long_txt_strings_are_concatenated(self):
        value = "v=DKIM1; k=rsa; p=" + "A" * 400
        answer = dns.parse_response(response("s._domainkey.x", dns.TXT, [txt_rdata(value)]))
        self.assertEqual(answer.records[0], value)

    def test_mx_record_with_compression(self):
        rdata = struct.pack(">H", 10) + dns.encode_name("mail.example.org")
        answer = dns.parse_response(response("example.org", dns.MX, [rdata]))
        self.assertEqual(answer.records[0].preference, 10)
        self.assertEqual(answer.records[0].exchange, "mail.example.org")

    def test_nxdomain_is_determinable_but_empty(self):
        answer = dns.parse_response(response("nope.example.org", dns.A, [], rcode=dns.NXDOMAIN))
        self.assertTrue(answer.nxdomain)
        self.assertTrue(answer.determinable)
        self.assertFalse(answer.exists)

    def test_servfail_is_not_determinable(self):
        answer = dns.parse_response(response("x.example.org", dns.A, [], rcode=dns.SERVFAIL))
        self.assertFalse(answer.determinable)

    def test_ad_flag_is_read(self):
        answer = dns.parse_response(response("example.org", dns.A, [], ad=True))
        self.assertTrue(answer.authenticated)

    def test_transaction_id_mismatch_is_rejected(self):
        packet = response("example.org", dns.TXT, [txt_rdata("x")])
        with self.assertRaises(dns.DNSError):
            dns.parse_response(packet, 0x1111)

    def test_compression_loop_is_rejected(self):
        packet = struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(dns.DNSError):
            dns.parse_response(packet)

    def test_query_carries_an_edns_record(self):
        packet, _ = dns.build_query("example.org", dns.TXT)
        self.assertEqual(struct.unpack(">H", packet[10:12])[0], 1)

    def test_idna_labels(self):
        self.assertIn(b"xn--", dns.encode_name("españa.es"))


class TestSPF(unittest.TestCase):
    def test_detects_records_case_insensitively(self):
        self.assertTrue(spf.is_spf("V=SPF1 -all"))
        self.assertFalse(spf.is_spf("google-site-verification=abc"))

    def test_parses_qualifier_and_includes(self):
        record = spf.parse("v=spf1 include:_spf.google.com ip4:1.2.3.4 ~all")
        self.assertEqual(record.all_qualifier, "~")
        self.assertEqual(record.includes, ["_spf.google.com"])

    def test_default_qualifier_is_pass(self):
        record = spf.parse("v=spf1 mx all")
        self.assertEqual(record.all_qualifier, "+")

    def test_redirect_modifier(self):
        record = spf.parse("v=spf1 redirect=_spf.example.net")
        self.assertEqual(record.redirect, "_spf.example.net")
        self.assertIsNone(record.all_qualifier)

    def test_missing_all_is_an_error(self):
        self.assertTrue(spf.parse("v=spf1 mx").errors)

    def test_ptr_is_detected(self):
        self.assertTrue(spf.parse("v=spf1 ptr -all").has_ptr)

    def test_lookup_counting_without_recursion(self):
        record = spf.parse("v=spf1 a mx include:a.com include:b.com ip4:1.2.3.4 -all")
        self.assertEqual(spf.count_lookups(record), 4)

    def test_lookup_counting_follows_includes(self):
        nested = {"a.com": spf.parse("v=spf1 a a a -all")}
        record = spf.parse("v=spf1 include:a.com -all")
        self.assertEqual(spf.count_lookups(record, nested.get), 4)

    def test_ip_mechanisms_do_not_count(self):
        record = spf.parse("v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 -all")
        self.assertEqual(spf.count_lookups(record), 0)

    def test_redirect_is_ignored_when_all_is_present(self):
        """RFC 7208 section 6.1: all wins, so redirect costs nothing."""
        record = spf.parse("v=spf1 ip4:1.2.3.4 -all redirect=big.example")
        self.assertIsNone(record.redirect)
        self.assertEqual(spf.count_lookups(record), 0)

    def test_macros_are_recognised(self):
        self.assertTrue(spf.has_macro("%{d}.spf.example"))
        self.assertFalse(spf.has_macro("_spf.google.com"))

    def test_include_cycles_terminate(self):
        records = {"a.com": spf.parse("v=spf1 include:b.com -all"),
                   "b.com": spf.parse("v=spf1 include:a.com -all")}
        record = spf.parse("v=spf1 include:a.com -all")
        self.assertLessEqual(spf.count_lookups(record, records.get), spf._CEILING)

    def test_diamond_include_graph_is_memoised(self):
        """The same include reached twice must not be counted twice over."""
        records = {
            "a.com": spf.parse("v=spf1 include:c.com -all"),
            "b.com": spf.parse("v=spf1 include:c.com -all"),
            "c.com": spf.parse("v=spf1 a a -all"),
        }
        record = spf.parse("v=spf1 include:a.com include:b.com -all")
        self.assertEqual(spf.count_lookups(record, records.get), 8)


class TestDMARC(unittest.TestCase):
    def test_parses_tags(self):
        record = dmarc.parse("v=DMARC1; p=reject; rua=mailto:a@b.com; pct=100; sp=none")
        self.assertEqual(record.policy, "reject")
        self.assertEqual(record.aggregate_reports, ["mailto:a@b.com"])
        self.assertEqual(record.subdomain_policy, "none")
        self.assertTrue(record.enforcing)

    def test_p_none_is_not_enforcing(self):
        self.assertFalse(dmarc.parse("v=DMARC1; p=none").enforcing)

    def test_partial_pct_is_not_enforcing(self):
        self.assertFalse(dmarc.parse("v=DMARC1; p=reject; pct=50").enforcing)

    def test_missing_policy_is_an_error(self):
        self.assertTrue(dmarc.parse("v=DMARC1; rua=mailto:a@b.com").errors)

    def test_invalid_policy_is_an_error(self):
        self.assertTrue(dmarc.parse("v=DMARC1; p=block").errors)

    def test_subdomain_policy_defaults_to_policy(self):
        self.assertEqual(
            dmarc.parse("v=DMARC1; p=quarantine").effective_subdomain_policy, "quarantine"
        )

    def test_external_report_domains(self):
        record = dmarc.parse("v=DMARC1; p=none; rua=mailto:x@reports.vendor.com,mailto:y@own.es")
        self.assertEqual(dmarc.external_report_domains(record, "own.es"), ["reports.vendor.com"])

    def test_report_address_with_size_limit(self):
        record = dmarc.parse("v=DMARC1; p=none; rua=mailto:x@vendor.com!10m")
        self.assertEqual(dmarc.external_report_domains(record, "own.es"), ["vendor.com"])

    def test_subdomain_of_the_audited_domain_is_not_external(self):
        record = dmarc.parse("v=DMARC1; p=none; rua=mailto:x@mail.own.es")
        self.assertEqual(dmarc.external_report_domains(record, "own.es"), [])


class TestDKIM(unittest.TestCase):
    def key_record(self, bits: int) -> str:
        subprocess.run(["openssl", "genrsa", "-out", f"/tmp/spoof{bits}.pem", str(bits)],
                       capture_output=True, check=False)
        der = subprocess.run(
            ["openssl", "rsa", "-in", f"/tmp/spoof{bits}.pem", "-pubout", "-outform", "DER"],
            capture_output=True, check=False,
        ).stdout
        return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()

    def test_detects_key_size(self):
        for bits in (1024, 2048):
            key = dkim.parse("s", self.key_record(bits))
            self.assertEqual(key.bits, bits)

    def test_revoked_key(self):
        key = dkim.parse("s", "v=DKIM1; k=rsa; p=")
        self.assertTrue(key.revoked)

    def test_test_mode(self):
        self.assertTrue(dkim.parse("s", "v=DKIM1; t=y; p=AAAA").testing)
        self.assertFalse(dkim.parse("s", "v=DKIM1; p=AAAA").testing)

    def test_missing_key_is_an_error(self):
        self.assertTrue(dkim.parse("s", "v=DKIM1; k=rsa").errors)

    def test_malformed_key_gives_no_size(self):
        self.assertIsNone(dkim.parse("s", "v=DKIM1; k=rsa; p=not-base64!!").bits)


if __name__ == "__main__":
    unittest.main()
