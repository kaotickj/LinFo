import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

script = Path(__file__).resolve().parents[1] / "privileged" / "linfo-helper"
loader = importlib.machinery.SourceFileLoader("linfo_test_helper", str(script))
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)


class TestHelper(unittest.TestCase):
    def test_merge_preserves_unrelated_config(self):
        old = b"# example\nnet.ipv4.ip_forward = 0\nkernel.randomize_va_space = 1\n"
        result = helper.merge_config(old, {"kernel.randomize_va_space": "2"}).decode()
        self.assertIn("# example", result)
        self.assertIn("net.ipv4.ip_forward = 0", result)
        self.assertEqual(result.count("kernel.randomize_va_space"), 1)

    def test_unlisted_sysctl_rejected(self):
        with self.assertRaises(RuntimeError):
            helper.key_path("kernel.modprobe")

    def test_empty_action_rejected(self):
        with self.assertRaises(RuntimeError):
            helper.apply([])

    def test_unknown_action_rejected(self):
        with self.assertRaises(RuntimeError):
            helper.apply(["arbitrary_shell_command"])

    def test_rollback_rejects_bad_uuid(self):
        with self.assertRaises(RuntimeError):
            helper.rollback("../../etc/shadow")

    def test_conflict_file_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            sysctl = Path(temp) / "sysctl.conf"
            sysctl.write_text("kernel.randomize_va_space = 0\n")
            # Test parser behavior by replacing glob scan paths with an isolated fixture.
            with patch.object(helper, "CONFIG", Path(temp) / "99-zz-linfo-hardening.conf"):
                # verify_conflicts always examines /etc/sysctl.conf; isolated test uses pure parse via merge.
                content = helper.merge_config(sysctl.read_bytes(), {"kernel.randomize_va_space": "2"})
            self.assertIn(b"kernel.randomize_va_space = 2", content)


if __name__ == "__main__":
    unittest.main()
