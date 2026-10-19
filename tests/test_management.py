import unittest
from linfo.management import detect_platform, actions_for, editor_command, parse_os_release
from linfo.models import Finding

class TestManagement(unittest.TestCase):
    def test_detect_debian(self):
        p = detect_platform('ID=debian\nPRETTY_NAME="Debian 13"', which=lambda x: '/usr/bin/apt' if x == 'apt' else None)
        self.assertEqual(p.package_manager, 'apt')
        self.assertEqual(p.admin_group, 'sudo')

    def test_detect_fedora(self):
        p = detect_platform('ID=fedora\nID_LIKE="rhel"', which=lambda x: '/usr/bin/dnf' if x == 'dnf' else None)
        self.assertEqual(p.package_manager, 'dnf')
        self.assertEqual(p.admin_group, 'wheel')

    def test_bad_editor_path_rejected(self):
        with self.assertRaises(ValueError):
            editor_command('/etc/passwd', '/usr/bin/kate')

    def test_unmanaged_control_kept_manual(self):
        f = Finding('account.uid0', 'Accounts', 'Extra UID0', 'FAIL', 'high', 'Review')
        self.assertEqual(actions_for(f, detect_platform('ID=debian', which=lambda x: '/usr/bin/apt' if x == 'apt' else None)), [])

    def test_service_management_actions(self):
        f = Finding('svc.fail2ban.service', 'Monitoring', 'fail2ban', 'WARN', 'low', 'Inactive')
        p = detect_platform('ID=debian', which=lambda x: '/usr/bin/apt' if x == 'apt' else None)
        action_types = [a.args[:2] for a in actions_for(f, p)]
        self.assertIn(('package', 'install'), action_types)
        self.assertIn(('service', 'enable'), action_types)

if __name__ == '__main__':
    unittest.main()

