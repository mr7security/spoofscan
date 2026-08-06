"""The reports and the CLI must survive any posture, in both languages."""
import json
import os
import tempfile
import unittest

from spoofscan import checks, cli, eml, lookalike, report_console, report_html
from tests.test_checks import CLEAN, posture

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class TestReports(unittest.TestCase):
    def setUp(self):
        self.posture = posture(
            spf__records=[], spf__parsed=None,
            dmarc__records=[], dmarc__parsed=None,
            dnssec__ds=False,
            lookalike__registered=[{"domain": "exarnple.org", "kind": "homoglyph",
                                    "addresses": ["1.2.3.4"], "mx": ["mx.exarnple.org"],
                                    "can_receive_mail": True}],
        )
        self.findings = checks.run_domain(self.posture)
        with open(os.path.join(FIXTURES, "phishing.eml"), "rb") as handle:
            self.message = eml.load(handle.read()).as_dict()

    def test_html_is_self_contained(self):
        document = report_html.render(self.posture, self.findings)
        self.assertIn("<!DOCTYPE html>", document)
        self.assertNotIn("http://", document.split("</style>")[0])
        self.assertIn("DMA-01", document)
        self.assertIn("mp.s.1", document)

    def test_html_states_the_verdict(self):
        document = report_html.render(self.posture, self.findings)
        self.assertIn("verdict yes", document)
        self.assertIn("¿Puede un tercero enviar correo", document)

    def test_html_says_not_spoofable_for_a_clean_domain(self):
        self.assertIn("verdict no", report_html.render(CLEAN, []))

    def test_html_includes_the_message_section(self):
        document = report_html.render(self.posture, self.findings, self.message)
        self.assertIn("Mensaje analizado", document)
        self.assertIn("mail-envio-facturas.top", document)

    def test_html_suggests_records_when_they_are_missing(self):
        document = report_html.render(self.posture, self.findings)
        self.assertIn("v=DMARC1; p=none", document)

    def test_html_omits_suggestions_for_a_complete_domain(self):
        self.assertNotIn("Records to publish", report_html.render(CLEAN, []))

    def test_console_in_both_languages(self):
        for lang, expected in (("en", "Spoofable"), ("es", "Suplantable")):
            text = report_console.render(self.posture, self.findings, lang)
            self.assertIn(expected, text)
            self.assertIn("DMA-01", text)

    def test_console_summary_table(self):
        results = [
            {"posture": self.posture, "findings": self.findings},
            {"posture": CLEAN, "findings": []},
        ]
        table = report_console.render_summary(results, "es")
        self.assertIn("example.org", table)
        self.assertIn("reject", table)

    def test_json_is_serialisable(self):
        payload = cli._serialise(self.posture, self.findings, self.message)
        encoded = json.dumps(payload)
        self.assertIn("spoofscan", encoded)
        self.assertTrue(payload["spoofable"])
        self.assertEqual(len(payload["findings"]), len(payload["findings_es"]))

    def test_soa_workbook(self):
        try:
            from spoofscan import report_soa
        except ImportError:
            self.skipTest("openpyxl not installed")
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as handle:
            path = handle.name
        try:
            report_soa.write(path, self.posture, self.findings, "es")
        except RuntimeError:
            self.skipTest("openpyxl not installed")
        with open(path, "rb") as written:
            self.assertGreater(len(written.read()), 1000)
        os.unlink(path)


class TestCli(unittest.TestCase):
    def run_cli(self, argv):
        return cli.main(argv)

    def test_from_posture_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "posture.json")
            with open(source, "w", encoding="utf-8") as handle:
                json.dump(CLEAN, handle)
            report = os.path.join(tmp, "report.html")
            code = self.run_cli(["--from-posture", source, "-o", report, "--quiet"])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(report))

    def test_posture_file_must_be_an_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "bad.json")
            with open(source, "w", encoding="utf-8") as handle:
                handle.write("[]")
            self.assertEqual(self.run_cli(["--from-posture", source, "--quiet"]), 1)

    def test_broken_posture_sections_are_tolerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "weird.json")
            with open(source, "w", encoding="utf-8") as handle:
                json.dump({"domain": "x.es", "spf": "not-a-dict", "collection": 7}, handle)
            report = os.path.join(tmp, "r.html")
            self.assertEqual(
                self.run_cli(["--from-posture", source, "-o", report, "--quiet"]), 0
            )

    def test_unwritable_output_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "posture.json")
            with open(source, "w", encoding="utf-8") as handle:
                json.dump(CLEAN, handle)
            code = self.run_cli(
                ["--from-posture", source, "-o", "/proc/nope/r.html", "--quiet"]
            )
            self.assertEqual(code, 1)

    def test_no_domain_is_an_error(self):
        self.assertEqual(self.run_cli(["--quiet", "--no-report"]), 1)

    def test_failing_domain_sets_exit_code_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "posture.json")
            with open(source, "w", encoding="utf-8") as handle:
                json.dump(posture(dmarc__records=[], dmarc__parsed=None), handle)
            code = self.run_cli(
                ["--from-posture", source, "--no-report", "--quiet"]
            )
            self.assertEqual(code, 2)


class TestLookalikeGeneration(unittest.TestCase):
    def test_registrable_name_is_extracted(self):
        self.assertEqual(lookalike.split_domain("sede.ayuntamiento.gob.es"),
                         ("ayuntamiento", "gob.es"))
        self.assertEqual(lookalike.split_domain("example.com"), ("example", "com"))

    def test_candidates_exclude_the_domain_itself(self):
        names = [c["domain"] for c in lookalike.generate("example.com")]
        self.assertNotIn("example.com", names)

    def test_candidates_are_unique(self):
        names = [c["domain"] for c in lookalike.generate("example.com")]
        self.assertEqual(len(names), len(set(names)))

    def test_limit_is_honoured(self):
        self.assertLessEqual(len(lookalike.generate("example.com", limit=20)), 20)

    def test_homoglyph_family_is_produced(self):
        names = [c["domain"] for c in lookalike.generate("example.com", limit=1000)]
        self.assertIn("exarnple.com", names)

    def test_alternative_tlds_are_produced(self):
        names = [c["domain"] for c in lookalike.generate("example.com", limit=1000)]
        self.assertIn("example.es", names)

    def test_every_candidate_has_a_known_family(self):
        for candidate in lookalike.generate("example.com"):
            self.assertNotEqual(lookalike.kind_label(candidate["kind"])[0], candidate["kind"])


if __name__ == "__main__":
    unittest.main()
