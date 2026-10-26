"""Regression cases for offline adapters and incomplete package evidence."""
import unittest

from linfo.checks import package_findings
from linfo.package_updates import (
    CACHED_COMMANDS, apt_automatic_finding, cached_update_finding,
    parse_apt_updates, parse_pacman_updates, parse_zypper_updates,
)
from linfo.probe import Result


class FakeProbe:
    def __init__(self, outputs=None, manager="apt", release='ID="debian"\n'):
        self.outputs = outputs or {}
        self.manager = manager
        self.release = release
        self.calls = []

    def which(self, name):
        return "/usr/bin/" + name if name == self.manager else None

    def read(self, path, max_size=120000):
        return self.release if path == "/etc/os-release" else None

    def run(self, *args, **kwargs):
        self.calls.append(tuple(args))
        return self.outputs.get(tuple(args), self.outputs.get(args[0], Result(False, error="Command unavailable", missing=True)))


class CachedUpdateTests(unittest.TestCase):
    def test_all_adapters_query_local_metadata(self):
        self.assertEqual(CACHED_COMMANDS["apt"], ("apt", "list", "--upgradable"))
        self.assertIn("--cacheonly", CACHED_COMMANDS["dnf"])
        self.assertIn("--setopt=plugins=0", CACHED_COMMANDS["dnf"])
        self.assertIn("--cacheonly", CACHED_COMMANDS["yum"])
        self.assertIn("--noplugins", CACHED_COMMANDS["yum"])
        self.assertIn("--no-refresh", CACHED_COMMANDS["zypper"])
        self.assertIn("--xmlout", CACHED_COMMANDS["zypper"])
        self.assertIn("-Qu", CACHED_COMMANDS["pacman"])
        self.assertFalse(any("checkupdates" in command for command in CACHED_COMMANDS.values()))

    def test_apt_listing_and_packages_are_distinct(self):
        text = "Listing... Done\nopenssl/stable-security 3.0.2 amd64 [upgradable from: 3.0.1]\n"
        self.assertEqual(parse_apt_updates(text), (["openssl"], True))
        result = cached_update_finding(FakeProbe({"apt": Result(True, text, returncode=0)}), "apt")
        self.assertEqual(result.status, "WARN")
        self.assertIn("1 package update", result.summary)
        self.assertEqual(result.id, "package.pending")

    def test_empty_apt_cache_is_not_a_pass(self):
        result = cached_update_finding(FakeProbe({"apt": Result(True, "Listing... Done\n", returncode=0)}), "apt")
        self.assertEqual(result.status, "INFO")
        self.assertIn("not proof", result.evidence)

    def test_unrecognized_apt_output_is_unknown(self):
        result = cached_update_finding(FakeProbe({"apt": Result(True, "different localized output", returncode=0)}), "apt")
        self.assertEqual(result.status, "UNKNOWN")

    def test_apt_cache_permission_error_is_unknown(self):
        result = cached_update_finding(FakeProbe({"apt": Result(False, error="E: Permission denied", returncode=100)}), "apt")
        self.assertEqual(result.status, "UNKNOWN")

    def test_dnf_exit_100_is_expected_updates(self):
        probe = FakeProbe({"dnf": Result(False, "openssl.x86_64 1:3.2-1 updates\n", returncode=100)}, manager="dnf")
        result = cached_update_finding(probe, "dnf")
        self.assertEqual(result.status, "WARN")
        self.assertIn("openssl.x86_64", result.evidence)
        self.assertEqual(probe.calls, [CACHED_COMMANDS["dnf"]])

    def test_yum_exit_100_is_expected_updates(self):
        result = cached_update_finding(FakeProbe({"yum": Result(False, "openssl.x86_64 1.0-1 updates\n", returncode=100)}), "yum")
        self.assertEqual(result.status, "WARN")

    def test_dnf_unrecognized_listing_does_not_lose_documented_exit_status(self):
        result = cached_update_finding(FakeProbe({"dnf": Result(False, "new version output layout", returncode=100)}), "dnf")
        self.assertEqual(result.status, "WARN")
        self.assertIn("no exact package count", result.evidence)

    def test_rpm_empty_success_is_informational(self):
        for manager in ("dnf", "yum"):
            with self.subTest(manager=manager):
                result = cached_update_finding(FakeProbe({manager: Result(True, returncode=0)}), manager)
                self.assertEqual(result.status, "INFO")

    def test_dnf_missing_cache_does_not_count_as_zero(self):
        result = cached_update_finding(FakeProbe({"dnf": Result(True, error="Cache-only enabled but no cache for 'updates'", returncode=0)}), "dnf")
        self.assertEqual(result.status, "UNKNOWN")

    def test_timeout_or_truncation_overrides_expected_exit_100(self):
        for flags in ({"truncated": True}, {"timed_out": True}, {"missing": True}, {"cancelled": True}):
            with self.subTest(flags=flags):
                result = cached_update_finding(FakeProbe({"dnf": Result(False, "openssl.x86_64 3.0 updates", returncode=100, **flags)}), "dnf")
                self.assertEqual(result.status, "UNKNOWN")

    def test_failed_rpm_query_is_unknown(self):
        result = cached_update_finding(FakeProbe({"dnf": Result(False, error="Cannot read database", returncode=1)}), "dnf")
        self.assertEqual(result.status, "UNKNOWN")

    def test_zypper_xml_multiline_counts_records(self):
        text = '''<stream><update-list>
          <update kind="package" name="openssl" edition="3.2" arch="x86_64"/>
          <update kind="package" name="bash" edition="5.2" arch="x86_64"/>
        </update-list></stream>'''
        result = cached_update_finding(FakeProbe({"zypper": Result(True, text, returncode=0)}), "zypper")
        self.assertEqual(result.status, "WARN")
        self.assertIn("2 package update", result.summary)

    def test_zypper_empty_update_list_is_info(self):
        result = cached_update_finding(FakeProbe({"zypper": Result(True, "<stream><update-list/></stream>", returncode=0)}), "zypper")
        self.assertEqual(result.status, "INFO")

    def test_zypper_error_or_missing_update_list_is_unknown(self):
        texts = ["<stream/>", "<stream><message type='error'>error</message><update-list/></stream>",
                 "<stream><update-list>", "<!DOCTYPE stream><stream><update-list/></stream>"]
        for text in texts:
            with self.subTest(text=text):
                self.assertFalse(parse_zypper_updates(text)[1])
                result = cached_update_finding(FakeProbe({"zypper": Result(True, text, returncode=0)}), "zypper")
                self.assertEqual(result.status, "UNKNOWN")

    def test_zypper_skipped_repositories_are_unknown(self):
        result = cached_update_finding(FakeProbe({"zypper": Result(False, "<stream><update-list/></stream>", returncode=106)}), "zypper")
        self.assertEqual(result.status, "UNKNOWN")

    def test_pacman_only_blank_exit_one_is_empty_result(self):
        results = [(Result(False, returncode=1), "INFO"),
                   (Result(False, error="error: could not open database", returncode=1), "UNKNOWN"),
                   (Result(False, "linux 6.8 -> 6.9\n", returncode=1), "UNKNOWN"),
                   (Result(True, "linux 6.8 -> 6.9\n", returncode=0), "WARN")]
        for value, expected in results:
            with self.subTest(value=value):
                self.assertEqual(cached_update_finding(FakeProbe({"pacman": value}), "pacman").status, expected)

    def test_unrecognized_pacman_output_is_not_zero(self):
        self.assertFalse(parse_pacman_updates("unexpected format")[1])

    def test_diagnostic_redacts_repository_url_password(self):
        result = cached_update_finding(FakeProbe({"dnf": Result(False, "partial output", error="Could not open https://user:SECRET@example.invalid/cache", returncode=1)}), "dnf")
        self.assertNotIn("SECRET", result.evidence)
        self.assertNotIn("partial output", result.evidence)

    def test_quoted_distro_and_like_values_preserve_existing_ids(self):
        probe = FakeProbe({"apt": Result(True, "Listing... Done\n", returncode=0)}, release='ID="custom"\nID_LIKE="debian ubuntu"\n')
        rows = list(package_findings(probe, "workstation"))
        self.assertEqual([row.id for row in rows], ["package.pending", "package.automatic"])
        self.assertEqual(probe.calls[0], CACHED_COMMANDS["apt"])


class AutomaticUpdateTests(unittest.TestCase):
    def test_config_across_files_and_active_timer_is_assessed(self):
        outputs = {
            "dpkg-query": Result(True, "install ok installed", returncode=0),
            "apt-config": Result(True, 'APT::Periodic::Unattended-Upgrade "1";\nAcquire::Proxy "https://user:SECRET@example.invalid";\n', returncode=0),
            "systemctl": Result(True, "LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n", returncode=0),
        }
        row = apt_automatic_finding(FakeProbe(outputs))
        self.assertEqual(row.status, "PASS")
        self.assertEqual(row.id, "package.automatic")
        self.assertNotIn("SECRET", row.evidence)
        self.assertIn("does not establish", row.evidence)

    def test_package_presence_without_config_is_not_a_pass(self):
        row = apt_automatic_finding(FakeProbe({"dpkg-query": Result(True, "install ok installed", returncode=0),
                                             "apt-config": Result(True, "", returncode=0)}))
        self.assertEqual(row.status, "WARN")

    def test_effective_global_periodic_disable_is_respected(self):
        row = apt_automatic_finding(FakeProbe({"dpkg-query": Result(True, "install ok installed", returncode=0),
                                             "apt-config": Result(True, 'APT::Periodic::Enable "0";\nAPT::Periodic::Unattended-Upgrade "1";\n', returncode=0)}))
        self.assertEqual(row.status, "WARN")

    def test_truncated_config_cannot_pass(self):
        row = apt_automatic_finding(FakeProbe({"dpkg-query": Result(True, "install ok installed", returncode=0),
                                             "apt-config": Result(False, 'APT::Periodic::Unattended-Upgrade "1";\n', returncode=0, truncated=True)}))
        self.assertEqual(row.status, "UNKNOWN")

    def test_failed_package_query_is_unknown_not_absence(self):
        row = apt_automatic_finding(FakeProbe({"dpkg-query": Result(False, error="Permission denied", returncode=2),
                                             "apt-config": Result(True, '', returncode=0)}))
        self.assertEqual(row.status, "UNKNOWN")

    def test_no_standard_timer_is_not_assumed_disabled(self):
        row = apt_automatic_finding(FakeProbe({"dpkg-query": Result(True, "install ok installed", returncode=0),
                                             "apt-config": Result(True, 'APT::Periodic::Unattended-Upgrade "1";\n', returncode=0),
                                             "systemctl": Result(False, error="not running systemd", returncode=1)}))
        self.assertEqual(row.status, "INFO")
        self.assertIn("another scheduler", row.evidence)


if __name__ == "__main__":
    unittest.main()
