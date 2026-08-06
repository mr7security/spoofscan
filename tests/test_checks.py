"""Tests for the rule set, over synthetic postures."""
import copy
import unittest

from spoofscan import checks, scoring
from spoofscan.models import Severity, Status

#: A domain that is as well protected as DNS allows.
CLEAN = {
    "domain": "example.org",
    "collected_at": "2026-01-01T00:00:00+00:00",
    "collection": {"resolvers": ["9.9.9.9"], "resolvable": True, "nxdomain": False, "queries": 40},
    "spf": {
        "determinable": True,
        "records": ["v=spf1 mx -all"],
        "parsed": {"raw": "v=spf1 mx -all", "all": "-", "includes": [], "redirect": None,
                   "has_ptr": False, "mechanisms": ["mx", "-all"], "errors": []},
        "lookups": 1,
        "unresolved_includes": [],
    },
    "dkim": {
        "determinable": True, "probed": ["default", "selector1"],
        "found": [{"selector": "default", "key_type": "rsa", "bits": 2048,
                   "revoked": False, "testing": False, "errors": []}],
    },
    "dmarc": {
        "determinable": True,
        "records": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.org"],
        "parsed": {"raw": "v=DMARC1; p=reject; rua=mailto:dmarc@example.org",
                   "policy": "reject", "subdomain_policy": None,
                   "effective_subdomain_policy": "reject", "percentage": 100,
                   "rua": ["mailto:dmarc@example.org"], "ruf": [], "aspf": "s",
                   "adkim": "s", "enforcing": True, "errors": []},
        "external_reports": None,
    },
    "mx": {"determinable": True,
           "records": [{"preference": 10, "exchange": "mail.example.org"}], "null_mx": False},
    "dnssec": {"determinable": True, "authenticated": True, "ds": True},
    "mta_sts": {"determinable": True, "record": "v=STSv1; id=1", "policy": {"mode": "enforce"},
                "mode": "enforce", "policy_error": None},
    "tls_rpt": {"determinable": True, "record": "v=TLSRPTv1; rua=mailto:t@example.org"},
    "dane": {"determinable": True, "hosts": {"mail.example.org": True}},
    "lookalike": {"determinable": True, "generated": 120, "checked": 120, "registered": []},
}


def posture(**changes):
    data = copy.deepcopy(CLEAN)
    for path, value in changes.items():
        keys = path.split("__")
        node = data
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
    return data


def ids(findings):
    return {f.id for f in findings}


def only(findings, fid):
    matches = [f for f in findings if f.id == fid]
    assert matches, f"{fid} not raised; got {sorted(ids(findings))}"
    return matches[0]


class TestCleanDomain(unittest.TestCase):
    def test_no_findings(self):
        self.assertEqual(checks.run_domain(CLEAN), [])

    def test_scores_100(self):
        self.assertEqual(scoring.score(checks.run_domain(CLEAN)), 100)

    def test_is_not_spoofable(self):
        self.assertIs(checks.spoofable(CLEAN), False)

    def test_exit_code_zero(self):
        self.assertEqual(scoring.exit_code(checks.run_domain(CLEAN)), 0)


class TestSpoofableVerdict(unittest.TestCase):
    def test_no_dmarc_is_spoofable(self):
        data = posture(dmarc__records=[], dmarc__parsed=None)
        self.assertIs(checks.spoofable(data), True)

    def test_p_none_is_spoofable_even_with_perfect_spf(self):
        data = posture()
        data["dmarc"]["parsed"].update(policy="none", enforcing=False)
        self.assertIs(checks.spoofable(data), True)

    def test_partial_pct_is_spoofable(self):
        data = posture()
        data["dmarc"]["parsed"].update(percentage=20, enforcing=False)
        self.assertIs(checks.spoofable(data), True)

    def test_unresolvable_dmarc_gives_no_verdict(self):
        self.assertIsNone(checks.spoofable(posture(dmarc__determinable=False)))


class TestSPFRules(unittest.TestCase):
    def test_missing_spf(self):
        found = checks.check_spf(posture(spf__records=[], spf__parsed=None))
        self.assertEqual(only(found, "SPF-01").severity, Severity.HIGH)

    def test_plus_all_is_critical(self):
        data = posture()
        data["spf"]["parsed"]["all"] = "+"
        self.assertEqual(only(checks.check_spf(data), "SPF-02").severity, Severity.CRITICAL)

    def test_multiple_records(self):
        data = posture(spf__records=["v=spf1 -all", "v=spf1 mx ~all"])
        self.assertIn("SPF-03", ids(checks.check_spf(data)))

    def test_neutral_all(self):
        data = posture()
        data["spf"]["parsed"]["all"] = "?"
        self.assertIn("SPF-04", ids(checks.check_spf(data)))

    def test_missing_all_without_redirect(self):
        data = posture()
        data["spf"]["parsed"]["all"] = None
        self.assertIn("SPF-04", ids(checks.check_spf(data)))

    def test_redirect_replaces_all(self):
        data = posture()
        data["spf"]["parsed"].update(all=None, redirect="_spf.example.net")
        self.assertNotIn("SPF-04", ids(checks.check_spf(data)))

    def test_too_many_lookups(self):
        found = checks.check_spf(posture(spf__lookups=14))
        self.assertIn("14", only(found, "SPF-05").title.en)

    def test_exactly_ten_lookups_is_allowed(self):
        self.assertNotIn("SPF-05", ids(checks.check_spf(posture(spf__lookups=10))))

    def test_ptr_mechanism(self):
        data = posture()
        data["spf"]["parsed"]["has_ptr"] = True
        self.assertIn("SPF-06", ids(checks.check_spf(data)))

    def test_unresolved_include(self):
        data = posture(spf__unresolved_includes=["old-provider.com"])
        self.assertIn("old-provider.com", only(checks.check_spf(data), "SPF-07").detail.en)

    def test_undeterminable_spf_is_silent(self):
        self.assertEqual(checks.check_spf(posture(spf__determinable=False)), [])


class TestDMARCRules(unittest.TestCase):
    def test_missing_dmarc_is_critical(self):
        found = checks.check_dmarc(posture(dmarc__records=[], dmarc__parsed=None))
        self.assertEqual(only(found, "DMA-01").severity, Severity.CRITICAL)

    def test_p_none(self):
        data = posture()
        data["dmarc"]["parsed"].update(policy="none", enforcing=False)
        self.assertEqual(only(checks.check_dmarc(data), "DMA-02").severity, Severity.HIGH)

    def test_quarantine(self):
        data = posture()
        data["dmarc"]["parsed"].update(policy="quarantine", enforcing=True)
        self.assertIn("DMA-03", ids(checks.check_dmarc(data)))

    def test_missing_rua(self):
        data = posture()
        data["dmarc"]["parsed"]["rua"] = []
        self.assertIn("DMA-04", ids(checks.check_dmarc(data)))

    def test_partial_pct(self):
        data = posture()
        data["dmarc"]["parsed"]["percentage"] = 30
        self.assertIn("DMA-05", ids(checks.check_dmarc(data)))

    def test_multiple_records(self):
        data = posture(dmarc__records=["v=DMARC1; p=reject", "v=DMARC1; p=none"])
        self.assertIn("DMA-06", ids(checks.check_dmarc(data)))

    def test_subdomains_left_open(self):
        data = posture()
        data["dmarc"]["parsed"].update(subdomain_policy="none", effective_subdomain_policy="none")
        self.assertIn("DMA-07", ids(checks.check_dmarc(data)))

    def test_unauthorised_external_reports(self):
        data = posture(dmarc__external_reports={"vendor.com": False})
        self.assertIn("vendor.com", only(checks.check_dmarc(data), "DMA-08").detail.en)

    def test_authorised_external_reports_are_fine(self):
        data = posture(dmarc__external_reports={"vendor.com": True})
        self.assertNotIn("DMA-08", ids(checks.check_dmarc(data)))

    def test_undeterminable_external_reports_are_silent(self):
        data = posture(dmarc__external_reports={"vendor.com": None})
        self.assertNotIn("DMA-08", ids(checks.check_dmarc(data)))


class TestDKIMRules(unittest.TestCase):
    def test_no_selector_found_is_not_a_failure_claim(self):
        found = checks.check_dkim(posture(dkim__found=[]))
        finding = only(found, "DKI-01")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertIn("not proof", finding.detail.en)

    def test_short_key(self):
        data = posture(dkim__found=[{"selector": "s", "key_type": "rsa", "bits": 512,
                                     "revoked": False, "testing": False, "errors": []}])
        self.assertEqual(only(checks.check_dkim(data), "DKI-02").severity, Severity.HIGH)

    def test_1024_bit_key_is_flagged_as_legacy(self):
        data = posture(dkim__found=[{"selector": "s", "key_type": "rsa", "bits": 1024,
                                     "revoked": False, "testing": False, "errors": []}])
        found = checks.check_dkim(data)
        self.assertIn("DKI-04", ids(found))
        self.assertNotIn("DKI-02", ids(found))

    def test_test_mode(self):
        data = posture(dkim__found=[{"selector": "s", "key_type": "rsa", "bits": 2048,
                                     "revoked": False, "testing": True, "errors": []}])
        self.assertIn("DKI-03", ids(checks.check_dkim(data)))

    def test_unprobed_dkim_is_silent(self):
        self.assertEqual(checks.check_dkim(posture(dkim__determinable=False)), [])


class TestTransportRules(unittest.TestCase):
    def test_missing_mta_sts(self):
        data = posture(mta_sts__record=None, mta_sts__mode=None)
        self.assertIn("TRA-01", ids(checks.check_transport(data)))

    def test_mta_sts_testing_mode(self):
        self.assertIn("TRA-02", ids(checks.check_transport(posture(mta_sts__mode="testing"))))

    def test_missing_tls_rpt(self):
        self.assertIn("TRA-03", ids(checks.check_transport(posture(tls_rpt__record=None))))

    def test_unsigned_zone(self):
        self.assertIn("TRA-04", ids(checks.check_transport(posture(dnssec__ds=False))))

    def test_missing_dane(self):
        data = posture(dane__hosts={"mail.example.org": False})
        self.assertIn("TRA-05", ids(checks.check_transport(data)))

    def test_null_mx_domain_skips_transport_rules(self):
        data = posture(mx__records=[{"preference": 0, "exchange": ""}], mx__null_mx=True,
                       mta_sts__record=None, tls_rpt__record=None)
        self.assertEqual(ids(checks.check_transport(data)) & {"TRA-01", "TRA-03", "TRA-05"}, set())

    def test_domain_without_mx_still_receives_mail_on_its_a_record(self):
        """RFC 5321 section 5.1: no MX means the address record is the destination."""
        data = posture(mx__records=[], mta_sts__record=None, mta_sts__mode=None)
        self.assertIn("TRA-01", ids(checks.check_transport(data)))

    def test_announced_but_unusable_mta_sts(self):
        data = posture(mta_sts__mode=None, mta_sts__policy=None,
                       mta_sts__policy_error="HTTP 404")
        self.assertIn("TRA-06", ids(checks.check_transport(data)))

    def test_undeterminable_dnssec_is_silent(self):
        self.assertNotIn("TRA-04", ids(checks.check_transport(posture(dnssec__ds=None))))


class TestParkedDomain(unittest.TestCase):
    def test_domain_without_mx_or_dmarc(self):
        data = posture(mx__records=[], dmarc__records=[], dmarc__parsed=None)
        self.assertIn("MX-01", ids(checks.check_mx(data)))

    def test_null_mx_is_correct(self):
        data = posture(mx__records=[{"preference": 0, "exchange": ""}], mx__null_mx=True,
                       dmarc__records=[], dmarc__parsed=None)
        self.assertNotIn("MX-01", ids(checks.check_mx(data)))


class TestLookalikeRules(unittest.TestCase):
    def test_domain_with_mx_is_high(self):
        data = posture(lookalike__registered=[
            {"domain": "exarnple.org", "kind": "homoglyph", "addresses": ["1.2.3.4"],
             "mx": ["mail.exarnple.org"], "can_receive_mail": True}])
        self.assertEqual(only(checks.check_lookalike(data), "LKA-01").severity, Severity.HIGH)

    def test_domain_without_mx_is_medium(self):
        data = posture(lookalike__registered=[
            {"domain": "example.com", "kind": "tld", "addresses": ["1.2.3.4"],
             "mx": [], "can_receive_mail": False}])
        self.assertEqual(only(checks.check_lookalike(data), "LKA-02").severity, Severity.MEDIUM)

    def test_skipped_lookalike_search_is_silent(self):
        self.assertEqual(checks.check_lookalike(posture(lookalike__determinable=False)), [])


class TestScoring(unittest.TestCase):
    def test_missing_dmarc_costs_forty_points(self):
        found = checks.check_dmarc(posture(dmarc__records=[], dmarc__parsed=None))
        self.assertEqual(scoring.score(found), 60)

    def test_worst_case_is_zero(self):
        data = posture(
            spf__records=[], spf__parsed=None, spf__lookups=None,
            spf__unresolved_includes=["a.com"],
            dkim__found=[], dmarc__records=[], dmarc__parsed=None,
            mta_sts__record=None, mta_sts__mode=None, tls_rpt__record=None,
            dnssec__ds=False, dane__hosts={"mail.example.org": False},
            lookalike__registered=[
                {"domain": "exarnple.org", "kind": "homoglyph", "addresses": [],
                 "mx": ["m"], "can_receive_mail": True},
                {"domain": "example.com", "kind": "tld", "addresses": ["1.2.3.4"],
                 "mx": [], "can_receive_mail": False}],
        )
        self.assertEqual(scoring.score(checks.run_domain(data)), 0)

    def test_control_status_marks_non_compliance(self):
        found = checks.check_dmarc(posture(dmarc__records=[], dmarc__parsed=None))
        statuses = scoring.control_status(found, CLEAN)
        self.assertEqual(statuses["ENS:mp.s.1"]["status"], Status.NON_COMPLIANT)

    def test_assessed_control_without_findings_is_compliant(self):
        statuses = scoring.control_status([], CLEAN)
        self.assertEqual(statuses["ENS:mp.s.1"]["status"], Status.COMPLIANT)

    def test_message_controls_are_not_assessed_without_a_message(self):
        statuses = scoring.control_status([], CLEAN)
        self.assertEqual(statuses["ISO:5.26"]["status"], Status.NOT_ASSESSED)
        self.assertEqual(statuses["ENS:op.exp.6"]["status"], Status.NOT_ASSESSED)

    def test_unresolvable_domain_claims_nothing(self):
        data = posture()
        data["collection"]["resolvable"] = False
        statuses = scoring.control_status([], data)
        self.assertTrue(all(v["status"] == Status.NOT_ASSESSED for v in statuses.values()))

    def test_empty_posture_claims_nothing(self):
        statuses = scoring.control_status([], {})
        self.assertTrue(all(v["status"] == Status.NOT_ASSESSED for v in statuses.values()))

    def test_coverage_counts_evaluated_rules(self):
        self.assertEqual(
            scoring.coverage(CLEAN)["applicable"], len(checks.DOMAIN_RULES)
        )
        self.assertGreater(scoring.coverage(CLEAN)["evaluated"], 15)

    def test_coverage_drops_when_dns_fails(self):
        broken = {k: ({} if isinstance(v, dict) and k != "collection" else v)
                  for k, v in CLEAN.items()}
        self.assertEqual(scoring.coverage(broken)["evaluated"], 0)


class TestCatalogueIntegrity(unittest.TestCase):
    def test_every_rule_maps_to_known_controls(self):
        from spoofscan import catalog
        for rule, refs in checks.RULE_CONTROLS.items():
            for ref in refs:
                self.assertIn(ref, catalog.CONTROLS, f"{rule} cites unknown control {ref}")

    def test_every_control_is_used(self):
        from spoofscan import catalog
        used = {ref for refs in checks.RULE_CONTROLS.values() for ref in refs}
        self.assertEqual(set(catalog.CONTROLS) - used, set())

    def test_every_rule_has_a_severity(self):
        self.assertEqual(set(checks.RULE_CONTROLS), set(checks._SEVERITY))

    def test_rule_ids_are_unique_per_scope(self):
        self.assertEqual(len(set(checks.DOMAIN_RULES) & set(checks.MESSAGE_RULES)), 0)

    def test_every_domain_rule_is_evaluable_on_a_clean_posture(self):
        """Any rule that can never run would be dead code."""
        evaluable = scoring.evaluable_rules(CLEAN)
        never = set(checks.DOMAIN_RULES) - evaluable
        self.assertEqual(never, {"DMA-08"}, f"unexpectedly unevaluable: {never}")

    def test_lookalike_reference_points_at_the_right_reinforcement(self):
        """op.mon.3.r4.1 covers watching digital content, r2.1 covers vulnerability scanning."""
        data = posture(lookalike__registered=[
            {"domain": "x.es", "kind": "tld", "addresses": [], "mx": ["m"],
             "can_receive_mail": True}])
        self.assertEqual(only(checks.check_lookalike(data), "LKA-01").reference,
                         "op.mon.3.r4.1")


if __name__ == "__main__":
    unittest.main()


class TestNoEvidence(unittest.TestCase):
    """A domain nothing could be learned about must not get a good grade."""

    def test_empty_posture_has_no_score(self):
        self.assertIsNone(scoring.score([], {}))
        self.assertEqual(scoring.grade(None), "n/a")

    def test_scoring_without_a_posture_still_returns_a_number(self):
        self.assertEqual(scoring.score([]), 100)

    def test_unresolvable_domain_has_no_score(self):
        dead = {"domain": "x.es",
                "collection": {"resolvable": False, "queries": 8},
                "spf": {"determinable": False}, "dkim": {"determinable": False},
                "dmarc": {"determinable": False}, "mx": {"determinable": False},
                "dnssec": {"determinable": False}, "mta_sts": {"determinable": False},
                "tls_rpt": {"determinable": False}, "dane": {"determinable": False},
                "lookalike": {"determinable": False}, "retention": {}}
        self.assertEqual(checks.run_domain(dead), [])
        self.assertIsNone(scoring.score([], dead))
        self.assertEqual(scoring.coverage(dead)["evaluated"], 0)

    def test_a_clean_domain_still_scores(self):
        self.assertEqual(scoring.score([], CLEAN), 100)
