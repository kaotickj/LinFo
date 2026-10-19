import unittest
from unittest.mock import patch
from linfo.checks import ACTIONS, sysctl_findings, account_findings
from linfo.models import AuditReport, Finding
from linfo.probe import Probe
from linfo.reports import compare_reports, render_html


class TestAssessment(unittest.TestCase):
    def test_no_duplicate_action_keys(self):
        names = [key for values in ACTIONS.values() for key in values]
        self.assertEqual(len(names), len(set(names)))

    def test_unknown_when_sysctl_missing(self):
        p = Probe()
        with patch.object(p, "sysctl", return_value=None):
            rows = list(sysctl_findings(p, "server"))
        self.assertTrue(rows)
        self.assertTrue(all(f.status == "UNKNOWN" for f in rows))

    def test_stricter_ptrace_pass(self):
        p = Probe()
        with patch.object(p, "sysctl", side_effect=lambda key: "2" if "ptrace_scope" in key else "0"):
            rows = list(sysctl_findings(p, "server"))
        self.assertEqual(next(x for x in rows if x.id == "sysctl.ptrace").status, "PASS")

    def test_uid0_detection(self):
        import pwd
        p = Probe()
        mockusers = [pwd.struct_passwd(("root", "x", 0, 0, "", "/root", "/bin/bash")),
                     pwd.struct_passwd(("badadmin", "x", 0, 0, "", "/root", "/bin/bash"))]
        with patch("linfo.checks.pwd.getpwall", return_value=mockusers):
            rows = list(account_findings(p, "server"))
        item = next(x for x in rows if x.id == "account.uid0")
        self.assertEqual(item.status, "FAIL")
        self.assertIn("badadmin", item.evidence)

    def test_html_escapes_content(self):
        report = AuditReport("workstation", {"host": "<tag>"},
                             [Finding("test", "Network", "<script>", "PASS", "low", "fine")])
        output = render_html(report)
        self.assertIn("&lt;script&gt;", output)
        self.assertNotIn("<script>", output)

    def test_compare_changed_control(self):
        report = AuditReport("server", {}, [Finding("sysctl.aslr", "Kernel", "ASLR", "PASS", "high", "")])
        previous = {"findings": [{"id": "sysctl.aslr", "status": "WARN", "title": "ASLR"}]}
        comparison = compare_reports(previous, report)
        self.assertEqual(comparison["changes"][0]["was"], "WARN")
        self.assertEqual(comparison["changes"][0]["now"], "PASS")


if __name__ == "__main__":
    unittest.main()
