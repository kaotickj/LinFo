"""Regression coverage for incomplete evidence and false security passes."""
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from linfo.checks import (account_findings, command_service, extra_findings,
                          firewall_findings, integrity_findings, network_findings,
                          sysctl_findings)
from linfo.extra_checks import module_findings, path_entry_note, process_findings, process_indicator
from linfo.probe import Result


class FakeProbe:
    def __init__(self, tools=(), commands=None, files=None):
        self.tools = set(tools)
        self.commands = commands or {}
        self.files = files or {}
        self.calls = []
        self.read_issues = {}
    def which(self, name):
        return "/usr/bin/" + name if name in self.tools else None
    def run(self, *args, **kwargs):
        self.calls.append(args)
        return self.commands.get(args, Result(False, error="Permission denied", returncode=1))
    def read(self, path, max_size=120000):
        return self.files.get(str(path))
    def sysctl(self, key):
        return self.files.get(key)
    def check_cancelled(self):
        pass


def by_id(rows, ident):
    return next(row for row in rows if row.id == ident)


class FirewallRegressionTests(unittest.TestCase):
    def test_manager_active_does_not_prove_firewall_protection(self):
        for name, command, output in (("ufw", ("ufw", "status"), "Status: active\n"),
                                      ("firewall-cmd", ("firewall-cmd", "--state"), "running\n")):
            with self.subTest(manager=name):
                p = FakeProbe((name,), {command: Result(True, output, returncode=0)})
                row = next(firewall_findings(p, "server"))
                self.assertEqual(row.id, "network.firewall")
                self.assertEqual(row.status, "UNKNOWN")

    def test_empty_nft_does_not_hide_legacy_ipv4_ipv6_policies(self):
        p = FakeProbe(("nft", "iptables", "ip6tables"), {
            ("nft", "-j", "-n", "list", "ruleset"): Result(True, '{"nftables": []}', returncode=0),
            ("iptables", "-S"): Result(True, "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n", returncode=0),
            ("ip6tables", "-S"): Result(True, "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n", returncode=0)})
        row = next(firewall_findings(p, "server"))
        self.assertEqual(row.status, "WARN")
        self.assertIn("IPv4 iptables", row.evidence)
        self.assertIn("IPv6 iptables", row.evidence)
        self.assertIn("INPUT=DROP", row.evidence)
        self.assertIn(("ip6tables", "-S"), p.calls)

    def test_denied_firewall_is_unknown(self):
        row = next(firewall_findings(FakeProbe(("nft",)), "server"))
        self.assertEqual(row.status, "UNKNOWN")

    def test_partial_nft_success_is_unknown(self):
        p = FakeProbe(("nft",), {("nft", "-j", "-n", "list", "ruleset"): Result(True, '{"nftables": []}', returncode=0, truncated=True)})
        self.assertEqual(next(firewall_findings(p, "server")).status, "UNKNOWN")

    def test_malformed_nft_shape_is_unknown(self):
        p = FakeProbe(("nft",), {("nft", "-j", "-n", "list", "ruleset"): Result(True, "[]", returncode=0)})
        self.assertEqual(next(firewall_findings(p, "server")).status, "UNKNOWN")


class RuntimeRegressionTests(unittest.TestCase):
    def test_service_timeout_cannot_return_active(self):
        p = FakeProbe(("systemctl",), {("systemctl", "is-active", "auditd.service"): Result(True, "active", returncode=0, timed_out=True)})
        self.assertIsNone(command_service(p, "auditd.service"))

    def test_known_inactive_exit_status_remains_inventory(self):
        p = FakeProbe(("systemctl",), {("systemctl", "is-active", "auditd.service"): Result(False, "inactive", returncode=3)})
        self.assertEqual(command_service(p, "auditd.service"), "inactive")

    def test_apparmor_enabled_without_profile_visibility_not_pass(self):
        p = FakeProbe(files={"/sys/module/apparmor/parameters/enabled": "Y\n", "/sys/kernel/security/lsm": "capability,apparmor"})
        row = by_id(integrity_findings(p, "server"), "kernel.lsm")
        self.assertEqual(row.status, "UNKNOWN")

    def test_apparmor_complain_profiles_not_enforcement_pass(self):
        p = FakeProbe(files={"/sys/module/apparmor/parameters/enabled": "Y\n", "/sys/kernel/security/apparmor/profiles": "test (complain)\n"})
        row = by_id(integrity_findings(p, "server"), "kernel.lsm")
        self.assertEqual(row.status, "WARN")

    def test_unknown_diagnostic_sysctl_does_not_pass(self):
        p = FakeProbe(files={"/proc/sys/kernel/kptr_restrict": "garbage"})
        row = by_id(integrity_findings(p, "server"), "kernel.kptr_restrict")
        self.assertEqual(row.status, "UNKNOWN")

    def test_yama_invalid_value_does_not_offer_remediation(self):
        p = FakeProbe(files={"kernel.yama.ptrace_scope": "9"})
        row = by_id(sysctl_findings(p, "server"), "sysctl.ptrace")
        self.assertEqual(row.status, "UNKNOWN")
        self.assertIsNone(row.action_id)

    def test_yama_three_describes_per_reboot_constraint(self):
        p = FakeProbe(files={"kernel.yama.ptrace_scope": "3"})
        row = by_id(sysctl_findings(p, "server"), "sysctl.ptrace")
        self.assertEqual(row.status, "PASS")
        self.assertIn("reboot", row.evidence)

    def test_partial_socket_list_does_not_pass_exposure_check(self):
        p = FakeProbe(commands={("ss", "-H", "-lntu"): Result(True, "", returncode=0, truncated=True)})
        rows = list(network_findings(p, "server"))
        self.assertEqual(by_id(rows, "network.exposed").status, "UNKNOWN")

    def test_udp_unconn_wildcard_is_evaluated(self):
        p = FakeProbe(commands={("ss", "-H", "-lntu"): Result(True, "udp UNCONN 0 0 0.0.0.0:3306 0.0.0.0:*\n", returncode=0)})
        self.assertEqual(by_id(network_findings(p, "server"), "network.exposed").status, "WARN")


class MetadataRegressionTests(unittest.TestCase):
    def account_file(self, shadow_mode, shadow_owner=0):
        def fake_stat(path, **kwargs):
            path = str(path)
            mode = stat.S_IFREG | (shadow_mode if path == "/etc/shadow" else 0o644 if path == "/etc/passwd" else 0o640)
            uid = shadow_owner if path == "/etc/shadow" else 0
            if path in ("/tmp", "/var/tmp", "/dev/shm"):
                mode = stat.S_IFDIR | 0o1777
            return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))
        with patch("linfo.checks.os.stat", side_effect=fake_stat), patch("linfo.checks.pwd.getpwall", return_value=[]), patch("linfo.checks.grp.getgrall", return_value=[]):
            return list(account_findings(FakeProbe(), "server"))

    def test_group_writable_shadow_fails(self):
        self.assertEqual(by_id(self.account_file(0o660), "file.shadow").status, "FAIL")

    def test_nonroot_owned_shadow_fails(self):
        self.assertEqual(by_id(self.account_file(0o600, 1000), "file.shadow").status, "FAIL")

    def test_expected_group_readable_shadow_and_public_passwd_pass(self):
        rows = self.account_file(0o640)
        self.assertEqual(by_id(rows, "file.shadow").status, "PASS")
        self.assertEqual(by_id(rows, "file.passwd").status, "PASS")

    def test_pam_reference_only_does_not_claim_enforcement(self):
        path = "/etc/pam.d/common-password"
        p = FakeProbe(files={path: "password optional pam_pwquality.so retry=3\n"})
        with patch.object(Path, "exists", lambda self: str(self) == path):
            row = by_id(extra_findings(p, "server"), "auth.pam_quality")
        self.assertEqual(row.status, "INFO")

    def test_unreadable_pam_is_reported(self):
        path = "/etc/pam.d/common-password"
        with patch.object(Path, "exists", lambda self: str(self) == path):
            row = by_id(extra_findings(FakeProbe(), "server"), "auth.pam_quality")
        self.assertEqual(row.status, "UNKNOWN")

    def test_root_writable_standard_path_not_flagged(self):
        meta = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        self.assertFalse(path_entry_note("/usr/bin", meta, 0)[0])
        self.assertTrue(path_entry_note("", None, 0)[0])

    def test_process_substrings_not_malware_indicators(self):
        for name in ("sync", "rsync", "accounts-daemon"):
            self.assertFalse(process_indicator(name, name))
        self.assertTrue(process_indicator("ncat", "ncat -l 8080"))

    def test_process_args_never_exposed_on_incomplete_output(self):
        p = FakeProbe(commands={("ps", "-eo", "pid=,uid=,comm=,args="): Result(True, "1 0 curl --token SECRET_VALUE", returncode=0, truncated=True)})
        row = next(process_findings(p, "server"))
        self.assertEqual(row.status, "UNKNOWN")
        self.assertNotIn("SECRET_VALUE", row.evidence)

    def test_unavailable_module_metadata_not_unsigned(self):
        p = FakeProbe(("modinfo",), files={"/proc/modules": "example 100 0 - Live 0x000\n"})
        row = next(module_findings(p, "server"))
        self.assertEqual(row.status, "UNKNOWN")
        self.assertIn("No signer metadata: none observed", row.evidence)


if __name__ == "__main__":
    unittest.main()
