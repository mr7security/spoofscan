"""Tests for the forensic reading of a received message."""
import os
import unittest

from spoofscan import checks, eml

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name: str) -> eml.Message:
    with open(os.path.join(FIXTURES, name), "rb") as handle:
        return eml.load(handle.read())


def ids(findings):
    return {f.id for f in findings}


class TestParsing(unittest.TestCase):
    def setUp(self):
        self.phish = load("phishing.eml")
        self.good = load("legitimate.eml")

    def test_headers_are_read(self):
        self.assertEqual(self.phish.from_address, "pagos@mail-envio-facturas.top")
        self.assertEqual(self.phish.from_domain, "mail-envio-facturas.top")
        self.assertEqual(self.phish.return_path_domain, "mail-envio-facturas.top")
        self.assertEqual(self.phish.reply_to_domain, "contable-gestion.top")

    def test_authentication_results_are_read(self):
        self.assertEqual(self.phish.auth_results["spf"], "fail")
        self.assertEqual(self.phish.auth_results["dmarc"], "fail")
        self.assertEqual(self.phish.auth_results["header.from"], "example.org")

    def test_only_the_top_authentication_header_is_trusted(self):
        raw = (b"Authentication-Results: real.example.org; dmarc=fail\r\n"
               b"Authentication-Results: forged.example.org; dmarc=pass\r\n"
               b"From: a@b.com\r\n\r\nbody\r\n")
        self.assertEqual(eml.load(raw).auth_results["dmarc"], "fail")

    def test_received_chain(self):
        self.assertEqual(len(self.phish.received), 2)

    def test_dkim_domain_is_read(self):
        self.assertEqual(self.good.dkim_domains, ["example.org"])

    def test_attachments(self):
        self.assertEqual(self.phish.attachments[0].filename, "certificado_bancario.pdf.exe")
        self.assertTrue(self.phish.attachments[0].double_extension)

    def test_urls_are_extracted(self):
        self.assertTrue(any("198.51.100.77" in u for u in self.phish.urls))

    def test_malformed_message_does_not_raise(self):
        message = eml.load(b"\xff\xfe not really an email at all")
        self.assertIsInstance(message, eml.Message)


class TestObservations(unittest.TestCase):
    def setUp(self):
        self.phish = load("phishing.eml")
        self.good = load("legitimate.eml")

    def test_display_name_spoof_is_detected(self):
        self.assertEqual(eml.display_name_spoof(self.phish), "financiera@example.org")

    def test_legitimate_display_name_is_clean(self):
        self.assertIsNone(eml.display_name_spoof(self.good))

    def test_alignment(self):
        self.assertIs(eml.alignment(self.phish)["reply_to"], False)
        self.assertIs(eml.alignment(self.good)["spf"], True)
        self.assertIs(eml.alignment(self.good)["dkim"], True)

    def test_subdomain_is_aligned_in_relaxed_mode(self):
        self.assertTrue(eml._aligned("mail.example.org", "example.org"))
        self.assertFalse(eml._aligned("example.org", "example.com"))

    def test_suspicious_urls(self):
        reasons = dict(eml.suspicious_urls(self.phish)).values()
        self.assertIn("ip-literal", reasons)
        self.assertIn("deep-subdomain", reasons)

    def test_legitimate_urls_are_not_flagged(self):
        self.assertEqual(eml.suspicious_urls(self.good), [])

    def test_risky_attachments_report_the_sharpest_reason(self):
        """certificado_bancario.pdf.exe is an executable first, a disguise second."""
        self.assertEqual(eml.risky_attachments(self.phish)[0][1],
                         "executable-double-extension")

    def test_disguised_archive_is_reported_as_a_double_extension(self):
        message = eml.Message(attachments=[eml.Attachment("nomina.pdf.zip", "application/zip", 9)])
        self.assertEqual(eml.risky_attachments(message)[0][1], "double-extension")

    def test_plain_archive(self):
        message = eml.Message(attachments=[eml.Attachment("fotos.zip", "application/zip", 9)])
        self.assertEqual(eml.risky_attachments(message)[0][1], "archive")

    def test_macro_document_is_flagged(self):
        message = eml.Message(attachments=[eml.Attachment("pedido.xlsm", "application/x", 10)])
        self.assertEqual(eml.risky_attachments(message)[0][1], "macro-capable")


class TestAuthenticationResults(unittest.TestCase):
    def test_worst_verdict_in_the_header_wins(self):
        raw = (b"Authentication-Results: mx; dkim=pass header.d=a.com; dkim=fail header.d=b.com\r\n"
               b"From: a@b.com\r\n\r\nbody\r\n")
        self.assertEqual(eml.load(raw).auth_results["dkim"], "fail")

    def test_similar_header_names_are_not_matched(self):
        raw = (b"Authentication-Results: mx; x-dkim=pass; spf=fail\r\n"
               b"From: a@b.com\r\n\r\nbody\r\n")
        results = eml.load(raw).auth_results
        self.assertEqual(results.get("spf"), "fail")
        self.assertNotIn("dkim", results)

    def test_authserv_id_selects_our_own_stamp(self):
        raw = (b"Authentication-Results: forged.example; dmarc=pass\r\n"
               b"Authentication-Results: mx.midominio.es; dmarc=fail\r\n"
               b"From: a@b.com\r\n\r\nbody\r\n")
        message = eml.load(raw, authserv_id="mx.midominio.es")
        self.assertEqual(message.auth_results["dmarc"], "fail")
        self.assertTrue(message.auth_verified)

    def test_unknown_authserv_id_yields_no_verdict(self):
        raw = (b"Authentication-Results: forged.example; dmarc=pass\r\n"
               b"From: a@b.com\r\n\r\nbody\r\n")
        self.assertEqual(eml.load(raw, authserv_id="mx.midominio.es").auth_results, {})

    def test_bogus_charset_does_not_disable_the_analysis(self):
        raw = (b"From: a@b.com\r\nContent-Type: text/plain; charset=\"utf-88888\"\r\n\r\n"
               b"http://198.51.100.5/x\r\n")
        message = eml.load(raw)
        self.assertIsNone(message.parse_error)
        self.assertTrue(message.urls)


class TestOrganisationalAlignment(unittest.TestCase):
    def test_sibling_subdomains_align(self):
        self.assertTrue(eml._aligned("news.corp.example", "mail.corp.example"))

    def test_parent_and_child_align(self):
        self.assertTrue(eml._aligned("corp.example", "mail.corp.example"))

    def test_different_organisations_do_not_align(self):
        self.assertFalse(eml._aligned("corp.example", "corp.example.com"))
        self.assertFalse(eml._aligned("banco.es", "banco-seguro.es"))


class TestMessageRules(unittest.TestCase):
    def test_phishing_message_raises_the_expected_rules(self):
        found = ids(checks.check_message(load("phishing.eml")))
        self.assertIn("EML-01", found)   # dmarc=fail yet delivered
        self.assertIn("EML-03", found)   # display name carries another address
        self.assertIn("EML-04", found)   # reply-to elsewhere
        self.assertIn("EML-05", found)   # dangerous attachment
        self.assertIn("EML-06", found)   # suspicious links

    def test_legitimate_message_raises_nothing(self):
        self.assertEqual(checks.check_message(load("legitimate.eml")), [])

    def test_message_without_authentication_results_is_flagged_as_unprovable(self):
        raw = b"From: Someone <a@b.com>\r\nTo: c@d.com\r\nSubject: hi\r\n\r\nbody\r\n"
        found = checks.check_message(eml.load(raw))
        self.assertIn("EML-07", ids(found))

    def test_spf_fail_without_dkim(self):
        raw = (b"Authentication-Results: mx; spf=fail smtp.mailfrom=x.com; dkim=none\r\n"
               b"From: a@b.com\r\nTo: c@d.com\r\n\r\nbody\r\n")
        self.assertIn("EML-02", ids(checks.check_message(eml.load(raw))))

    def test_local_evidence_speaks_when_no_verdict_exists(self):
        raw = (b"Return-Path: <bounce@evil.tld>\r\n"
               b"DKIM-Signature: v=1; d=evil.tld; s=s; b=x\r\n"
               b"From: Facturas <facturas@corp.example>\r\n"
               b"To: a@corp.example\r\n\r\nbody\r\n")
        found = ids(checks.check_message(eml.load(raw)))
        self.assertIn("EML-08", found)
        self.assertIn("EML-07", found)

    def test_competing_authentication_headers_are_not_trusted(self):
        raw = (b"Authentication-Results: forged.example; spf=pass; dkim=pass; dmarc=pass\r\n"
               b"Authentication-Results: real.example; spf=pass; dkim=pass; dmarc=pass\r\n"
               b"Return-Path: <bounce@evil.tld>\r\n"
               b"From: Facturas <facturas@corp.example>\r\n\r\nbody\r\n")
        found = ids(checks.check_message(eml.load(raw)))
        self.assertIn("EML-07", found)

    def test_unparseable_message_raises_no_findings(self):
        self.assertEqual(checks.check_message(eml.Message(parse_error="boom")), [])


if __name__ == "__main__":
    unittest.main()
