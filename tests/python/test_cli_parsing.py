#!/usr/bin/env python3
"""Unit tests (stdlib unittest) for the vault_kernel CLI parsing layer.

Run directly — no external deps, mirroring the zero-dependency policy:

    python3 tests/python/test_cli_parsing.py -v

Wired into CI (Python job) since v3.6.  The suite pins the GET_STATS /
LIST_HIDDEN report formats emitted by src/ioctl.c and the regressions
fixed in v3.6: the multi-pair stats parser and the --interval units.
"""
import argparse
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
    "module=vault_kernel version=3.8\n"
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
            "version": "3.8",
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
        got = vk.parse_stats_report("module=vault_kernel version=3.8\n")
        self.assertEqual(got["module"], "vault_kernel")
        self.assertEqual(got["version"], "3.8")

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
        self.assertEqual(parsed["schema"], 1)
        self.assertEqual(parsed["module"], "vault_kernel")
        self.assertEqual(parsed["version"], "3.8")
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
        self.assertEqual(parsed["schema"], 1)
        self.assertTrue(parsed["device_present"])
        self.assertTrue(parsed["device_open"])
        self.assertTrue(parsed["stats_responds"])
        self.assertEqual(parsed["module_version"], "3.8")
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
            stats_report=STATS_REPORT.replace("version=3.8", "version=3.0"))
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
        self.assertEqual(parsed["schema"], 1)
        self.assertFalse(parsed["device_present"])
        self.assertNotIn("device_open", parsed)
        self.assertEqual(parsed["warnings"], 0)


class TestFormatWatchPanel(unittest.TestCase):
    """format_watch_panel is the user-facing layout contract of the new
    `watch` command (v3.7): keys sorted and column-aligned at the widest
    key, "(none)" for empty hidden sections, "(no stats)" placeholder.
    Mirrors TestRenderWatchPanel in the Go client."""

    STATS = {
        "module": "vault_kernel", "version": "3.8",
        "hooks_installed": "7", "hooks_planned": "7",
        "module_hidden": "0", "hidden_files": "1", "hidden_pids": "1",
        "hidden_ports": "1", "keylog_bytes": "0", "uptime_s": "42",
    }
    HIDDEN = {"pids": [1234, 567], "files": ["secret.txt",
                                              "my dir/with space.txt"],
              "ports": [8080]}

    def test_full_frame(self):
        got = vk.format_watch_panel(self.STATS, self.HIDDEN, 1000,
                                    "01:42:10")
        self.assertIn("vault_kernel watch — refresh 1000 ms — "
                      "updated 01:42:10 — Ctrl-C to stop", got)
        self.assertIn("== stats ==", got)
        self.assertIn("== hidden ==", got)
        # Keys sorted alphabetically.
        self.assertLess(got.index("hooks_installed"),
                        got.index("hooks_planned"))
        # Column alignment: widest key ("hooks_installed", 15) pads the
        # rest; the format adds " : " so "version" gets 9 spaces.
        self.assertIn("version         : 3.8", got)
        self.assertIn("pids : 1234, 567", got)
        self.assertIn("files: secret.txt, my dir/with space.txt", got)
        self.assertIn("ports: 8080", got)

    def test_empty_sections(self):
        got = vk.format_watch_panel({}, {"pids": [], "files": [],
                                         "ports": []}, 500, "00:00:00")
        self.assertIn("stats: (no stats)", got)
        self.assertIn("pids : (none)", got)
        self.assertIn("files: (none)", got)
        self.assertIn("ports: (none)", got)


class TestListJsonEndToEnd(unittest.TestCase):
    """list(as_json=True) against a stubbed ioctl: versioned envelope
    with the three sections (v3.7 added the schema marker)."""

    def test_list_json_complete(self):
        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None

        def fake_ioctl(request, buf=None):
            if buf is not None:
                data = LIST_REPORT.encode()
                buf[:len(data)] = data
            return True

        c._ioctl = fake_ioctl
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            c.list_hidden(as_json=True)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["schema"], 1)
        self.assertEqual(parsed["pids"], [1234, 567])
        self.assertEqual(parsed["files"],
                         ["secret.txt", "my dir/with space.txt"])
        self.assertEqual(parsed["ports"], [8080])

    def test_list_json_empty_sections(self):
        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None

        empty_report = ("--- Hidden PIDs ---\n--- Hidden Files ---\n"
                        "--- Hidden Ports ---\n")

        def fake_ioctl(request, buf=None):
            if buf is not None:
                data = empty_report.encode()
                buf[:len(data)] = data
            return True

        c._ioctl = fake_ioctl
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            c.list_hidden(as_json=True)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["schema"], 1)
        self.assertEqual(parsed["pids"], [])
        self.assertEqual(parsed["files"], [])
        self.assertEqual(parsed["ports"], [])


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


class TestIntervalArgType(unittest.TestCase):
    """v3.6 accepted float for --interval, so `--interval nan`/`inf`
    reached time.sleep() and died with a raw ValueError/OverflowError
    instead of a usage error.  v3.7 parses interval args with
    _ms_arg: integer text, no negatives, non-finite rejected by the
    int() conversion itself."""

    def test_accepts_integer_text(self):
        self.assertEqual(vk._ms_arg("500"), 500)
        self.assertEqual(vk._ms_arg("50"), 50)

    def test_rejects_non_integer_text(self):
        for bad in ("nan", "inf", "abc", "0.5"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                vk._ms_arg(bad)

    def test_rejects_negative(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            vk._ms_arg("-5")

    def test_watch_default_is_1000ms(self):
        self.assertEqual(vk.WATCH_DEFAULT_INTERVAL_MS, 1000)


class TestFormatKeylogEvent(unittest.TestCase):
    """format_keylog_event is the user-facing contract of one
    `keylog --follow` event (v3.8 added --timestamps) — mirrors
    TestFormatKeylogEvent in the Go client: timestamps put every event
    on a fresh [HH:MM:SS]-prefixed line; without them a suffix diff
    continues the line and a buffer wrap starts a new one."""

    def test_continuation_without_timestamps(self):
        self.assertEqual(vk.format_keylog_event("def"), "def")

    def test_wrap_without_timestamps(self):
        self.assertEqual(vk.format_keylog_event("wrapped", wrapped=True),
                         "\nwrapped")

    def test_timestamps_start_a_fresh_line(self):
        self.assertEqual(vk.format_keylog_event("def", "10:30:05"),
                         "\n[10:30:05] def")
        self.assertEqual(
            vk.format_keylog_event("wrapped", "10:30:05", wrapped=True),
            "\n[10:30:05] wrapped")

    def test_content_never_mangled(self):
        got = vk.format_keylog_event("my dir/with space.txt", "00:00:00")
        self.assertTrue(got.endswith("my dir/with space.txt"))


class TestVersionCommand(unittest.TestCase):
    """v3.8: the Python CLI gains `version` (the Go CLI had it since
    v3.6 — parity gap).  format_version_line mirrors Go's printVersion:
    same wording, same ioctl magic (0xC0) and signal trigger (35)."""

    def test_format_version_line(self):
        self.assertEqual(
            vk.format_version_line(),
            f"vault_kernel CLI v{vk.CLIENT_VERSION} "
            "(ioctl magic 0xC0, signal trigger 35)")

    def test_version_command_prints(self):
        out = io.StringIO()
        with mock.patch.object(vk.sys, "argv",
                               ["vault_kernel_cli.py", "version"]), \
             contextlib.redirect_stdout(out):
            vk.main()
        self.assertIn(vk.format_version_line(), out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
