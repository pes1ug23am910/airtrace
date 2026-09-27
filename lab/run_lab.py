"""Generate a dataset on an otherwise idle Linux host with root privileges."""

import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import subprocess
import time

from lab.manifest import git_commit, validate_meta, write_manifest
from lab.scenarios import CLASS_IDS, SCENARIOS, bundle_id, draw_parameters, render_configs, seed_schedule
from lab.scrub import SCRUB_RULES
from lab.verify import check_capture_health, verification_commands, verify_injection
from lab.outcomes import collect_observed, observation_commands
from lab.window import LogRecorder, clock_mark, trim_capture


COMMAND_TIMEOUT = 10
CONNECT_TIMEOUT = 30
OBSERVE_SECONDS = 30
RUN_TIMEOUT = 150


def command_plan(class_id: str, seed: int, directory: Path, phys=None, split="dev") -> tuple[list[dict], list[list[str]]]:
    """This single plan drives both execution and the non-root dry run."""
    p = draw_parameters(seed, split)
    token = bundle_id(class_id, seed)
    namespaces = [f"at-{token}-{role}" for role in ("ap", "sta", "occ")]
    ap, station, occupant = namespaces
    phys = phys or ["phy0", "phy1", "phy2"]
    root = str(directory)
    steps = []

    def add(kind, argv=None, **options):
        steps.append({"kind": kind, "argv": argv, **options})

    def run(argv):
        add("run", argv, timeout=COMMAND_TIMEOUT)

    def start(argv, log, required=True):
        add("start", ["timeout", "--signal=TERM", "--kill-after=3s", "140s", *argv],
            timeout=140, log=log, required=required)

    def ns(name, argv):
        return ["ip", "netns", "exec", name, *argv]

    run(["modprobe", "mac80211_hwsim", "radios=3"])
    run(["ip", "link", "set", "hwsim0", "up"])
    for index, (namespace, address) in enumerate(zip(namespaces, (p.ap_mac, p.station_mac, p.occupant_mac))):
        run(["ip", "netns", "add", namespace])
        run(["iw", "phy", phys[index], "set", "netns", "name", namespace])
        run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        run(["ip", "-n", namespace, "link", "set", f"wlan{index}", "address", address])
        run(["ip", "-n", namespace, "link", "set", f"wlan{index}", "up"])
    run(["ip", "-n", ap, "address", "add", "192.0.2.1/24", "dev", "wlan0"])
    start(["tcpdump", "-U", "-n", "-Z", "root", "-s", "0", "-i", "hwsim0", "-w", f"{root}/raw/capture.pcap"], "tcpdump.log")
    add("delay", seconds=0.5)
    if SCENARIOS[class_id].dhcp_server:
        start(ns(ap, ["dnsmasq", "--keep-in-foreground", f"--conf-file={root}/dnsmasq.conf"]), "dhcp_server.log")
    add("delay", seconds=p.ap_delay)
    start(ns(ap, ["hostapd", "-d", "-t", f"{root}/hostapd.conf"]), "hostapd.log")
    add("wait", ns(ap, ["hostapd_cli", "-p", f"{root}/ap-control", "-i", "wlan0", "ping"]),
        contains="PONG", timeout=CONNECT_TIMEOUT)
    if class_id == "ap_full":
        start(ns(occupant, ["wpa_supplicant", "-d", "-t", "-i", "wlan2", "-c", f"{root}/occupant.conf"]), "occupant.log")
        add("wait", ns(occupant, ["wpa_cli", "-p", f"{root}/occupant-control", "-i", "wlan2", "status"]),
            contains="wpa_state=COMPLETED", timeout=CONNECT_TIMEOUT)
        add("wait", ns(ap, ["hostapd_cli", "-p", f"{root}/ap-control", "-i", "wlan0", "sta", p.occupant_mac]),
            contains="[AUTHORIZED]", timeout=CONNECT_TIMEOUT)
    add("delay", seconds=p.station_delay)
    start(ns(station, ["wpa_supplicant", "-d", "-t", "-i", "wlan1", "-c", f"{root}/station.conf"]), "wpa_supplicant.log")
    start(ns(station, ["busybox", "udhcpc", "-f", "-n", "-q", "-t", "15", "-T", "2",
                       "-i", "wlan1", "-s", f"{root}/dhcp-script.sh",
                       "-p", f"{root}/udhcpc.pid"]), "dhcp_client.log", required=False)
    if class_id == "ap_deauth":
        add("wait", ns(station, ["wpa_cli", "-p", f"{root}/sta-control", "-i", "wlan1", "status"]),
            contains="wpa_state=COMPLETED", timeout=CONNECT_TIMEOUT)
        add("require", ns(ap, ["hostapd_cli", "-p", f"{root}/ap-control", "-i", "wlan0",
                              "deauthenticate", p.station_mac, "reason=3"]), contains="OK", timeout=COMMAND_TIMEOUT)
    add("delay", seconds=OBSERVE_SECONDS)
    cleanup = [["ip", "netns", "delete", name] for name in reversed(namespaces)]
    cleanup.append(["modprobe", "-r", "mac80211_hwsim"])
    return steps, cleanup


def show_plan(class_id: str, split: str, seed: int, directory: Path, phys=None, binary=None):
    steps, cleanup = command_plan(class_id, seed, directory, phys, split)
    print(f"# bundle={directory}, split={split}, seed={seed}")
    print(f"# create {directory / 'raw'} for daemon output and the untrimmed capture")
    for name, content in render_configs(class_id, draw_parameters(seed, split), str(directory)).items():
        print(f"# write {directory / name}: {json.dumps(content)}")
    if not SCENARIOS[class_id].dhcp_server:
        print(f"# create empty {directory / 'dhcp_server.log'}")
    for step in steps:
        if step["kind"] == "delay":
            print(f"# wait {step['seconds']} seconds")
        else:
            suffix = f" # {step['kind']}, timeout={step['timeout']}s"
            if "contains" in step:
                suffix += f", require stdout containing {step['contains']!r}"
            if "log" in step:
                suffix += f", record stdout/stderr and receipt times under {directory / 'raw' / step['log']}"
            if step.get("log") == "wpa_supplicant.log":
                print("# record scenario start wall clock and monotonic time")
            print(shlex.join(step["argv"]) + suffix)
    print("# close observation: record end clocks; SIGINT tcpdump and wait 3s, KILL and wait 3s if needed")
    print("# copy pcap records and original log lines at/before the end; freeze visible files before any verification query")
    for argv in verification_commands(class_id, seed, directory, draw_parameters(seed, split)).values():
        print(shlex.join(argv) + " # harness verification, timeout=10s; output only in metadata")
    for argv in observation_commands(class_id, seed, directory).values():
        print(shlex.join(argv) + " # final observed state, timeout=10s; output only in metadata")
    print("# finally: TERM each started process group; wait 3s, KILL if necessary; wait 3s")
    for argv in cleanup:
        print(shlex.join(argv) + f" # cleanup, timeout={COMMAND_TIMEOUT}s")
    capture_command = [str(binary or os.environ.get("AIRTRACE_BIN", "airtrace")), "parse", str(directory / "capture.pcap"), "--jsonl", "--stats"]
    print(shlex.join(capture_command) + " # capture health after cleanup, timeout=30s; output only in metadata")
    print("# control echoes are scrubbed during the immutable log snapshot; raw files are never model-visible")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class Executor:
    def __init__(self, directory: Path):
        self.directory = directory
        (directory / "raw").mkdir(exist_ok=True)
        self.deadline = time.monotonic() + RUN_TIMEOUT
        self.processes = []
        self.records = []
        self.namespaces = set()
        self.loaded_module = False
        self.recorders = {}
        self.observation_end = None
        self.observation_window = None
        self.capture_closed = False

    def remaining(self, timeout):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bundle exceeded its overall deadline")
        return min(timeout, remaining)

    def run(self, argv, timeout=COMMAND_TIMEOUT, check=True, cleanup=False):
        started = time.monotonic()
        record = {"argv": argv, "timeout": timeout}
        self.records.append(record)
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, errors="replace",
                timeout=timeout if cleanup else self.remaining(timeout), check=False,
            )
            record.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            if result.returncode == 0:
                if argv[:3] == ["ip", "netns", "add"]:
                    self.namespaces.add(argv[3])
                if argv[:2] == ["modprobe", "mac80211_hwsim"]:
                    self.loaded_module = True
            if check and result.returncode != 0:
                raise RuntimeError(f"command failed ({result.returncode}): {shlex.join(argv)}: {result.stderr[-1000:]}")
            return result
        except (OSError, subprocess.TimeoutExpired) as error:
            record["error"] = str(error)
            raise
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 6)

    def healthy(self):
        for process, stream, step in self.processes:
            if self.capture_closed and step["log"] == "tcpdump.log":
                continue
            if step["required"] and process.poll() is not None:
                raise RuntimeError(f"required process exited ({process.returncode}): {shlex.join(step['argv'])}")

    def execute(self, step):
        kind = step["kind"]
        self.healthy()
        if kind == "delay":
            if self.remaining(step["seconds"]) < step["seconds"]:
                raise TimeoutError("insufficient run time for the full observation or startup delay")
            time.sleep(step["seconds"])
        elif kind == "start":
            self.remaining(1)
            process = subprocess.Popen(step["argv"], stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            recorder = LogRecorder(process.stdout, self.directory / "raw" / step["log"])
            self.recorders[step["log"]] = recorder
            self.processes.append((process, recorder, step))
            recorder.start()
            self.records.append({"argv": step["argv"], "timeout": step["timeout"], "background": True, "log": step["log"]})
        elif kind == "wait":
            deadline = time.monotonic() + self.remaining(step["timeout"])
            while time.monotonic() < deadline:
                result = self.run(step["argv"], timeout=min(3, deadline - time.monotonic()), check=False)
                if result.returncode == 0 and step["contains"] in result.stdout:
                    return
                self.healthy()
                time.sleep(min(0.5, max(0, deadline - time.monotonic())))
            raise TimeoutError(f"precondition did not become true: {step['contains']}")
        else:
            result = self.run(step["argv"], step["timeout"])
            if kind == "require" and step["contains"] not in result.stdout:
                raise RuntimeError(f"precondition missing: {step['contains']}")

    def close_observation(self):
        """One cutoff for every class, before control queries or daemon cleanup."""
        if self.observation_window is not None:
            return self.observation_end, self.observation_window
        if self.observation_end is None:
            self.observation_end = clock_mark()
        self.capture_closed = True
        for process, recorder, step in self.processes:
            if step["log"] != "tcpdump.log":
                continue
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGINT)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=3)
            recorder.finish()
            self.records.append({"event": "capture_stopped", "returncode": process.returncode})
        logs = {}
        for source in ("hostapd", "wpa_supplicant", "dhcp_server", "dhcp_client"):
            filename = source + ".log"
            recorder = self.recorders.get(filename)
            if recorder is None:
                recorder = LogRecorder(io.BytesIO(b""), self.directory / "raw" / filename)
                recorder.start()
                recorder.finish()
            logs[source] = recorder.snapshot(self.directory / filename, self.observation_end,
                                             scrub=source in SCRUB_RULES["sources"])
        capture = trim_capture(self.directory / "raw" / "capture.pcap",
                               self.directory / "capture.pcap", self.observation_end)
        self.observation_window = {"version": "receipt-pcap-v1", "logs": logs, "capture": capture}
        self.records.append({"event": "observation_closed", **self.observation_end})
        return self.observation_end, self.observation_window

    def cleanup(self, commands):
        errors = []
        for process, recorder, step in reversed(self.processes):
            try:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=3)
                self.records.append({"argv": step["argv"], "cleanup_returncode": process.returncode})
            except (OSError, subprocess.TimeoutExpired) as error:
                errors.append(str(error))
            finally:
                try:
                    recorder.finish()
                except (OSError, RuntimeError, TimeoutError) as error:
                    errors.append(str(error))
        for argv in commands:
            if argv[:3] == ["ip", "netns", "delete"] and argv[3] not in self.namespaces:
                continue
            if argv[0] == "modprobe" and not self.loaded_module:
                continue
            try:
                self.run(argv, cleanup=True)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                errors.append(str(error))
        return errors


def tool_versions():
    versions = {}
    for name, argv in {
        "hostapd": ["hostapd", "-v"], "wpa_supplicant": ["wpa_supplicant", "-v"],
        "dnsmasq": ["dnsmasq", "--version"], "udhcpc": ["busybox", "udhcpc", "--help"],
        "tcpdump": ["tcpdump", "--version"], "iw": ["iw", "--version"],
        "ip": ["ip", "-Version"], "tshark": ["tshark", "--version"],
    }.items():
        try:
            result = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=10, check=False)
            versions[name] = (result.stdout + result.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as error:
            versions[name] = f"unavailable: {type(error).__name__}: {error}"
    versions["python"] = platform.python_version()
    return versions


def discover_phys():
    """Discover only the newly loaded radios; wiphy indices need not start at zero."""
    phys = sorted(path.name for path in Path("/sys/class/ieee80211").glob("*"))
    if len(phys) != 3:
        raise RuntimeError(f"expected three newly created phys, got {phys}")
    interfaces = {}
    for interface in Path("/sys/class/net").glob("wlan*"):
        phy_link = interface / "phy80211"
        if phy_link.exists():
            interfaces[interface.name] = phy_link.resolve().name
    if not all(f"wlan{i}" in interfaces for i in range(3)):
        raise RuntimeError(f"expected wlan0, wlan1, wlan2; found {interfaces}")
    return [interfaces[f"wlan{i}"] for i in range(3)]


def run_bundle(class_id, split, seed, directory, commit, versions, binary=None):
    directory.mkdir(parents=True, exist_ok=False)
    for name in ("capture.pcap", "hostapd.log", "wpa_supplicant.log", "dhcp_server.log", "dhcp_client.log"):
        (directory / name).touch()
    parameters = draw_parameters(seed, split)
    metadata = {
        "label": class_id, "seed": seed, "split": split, "parameters": parameters.as_dict(),
        "kernel": platform.release(), "tool_versions": versions, "started_at": utc_now(),
        "ended_at": utc_now(), "status": "failed", "error": None,
        "generator_commit": commit, "commands": [],
        "injection_verified": False, "verification": [],
        "capture_health": {"healthy": False, "ap_beacons": 0, "error": "not checked"},
        "quarantined": True, "quarantine_reasons": [], "log_scrub": {},
        "dhcp_server_started": False,
        "scenario_started_at": None, "scenario_started_monotonic_ns": None,
        "observation_end": None, "observation_window": None, "observed": None,
    }
    executor = Executor(directory)
    steps, cleanup = command_plan(class_id, seed, directory, split=split)
    try:
        for name, content in render_configs(class_id, parameters, str(directory)).items():
            (directory / name).write_text(content, encoding="utf-8", newline="\n")
        (directory / "dhcp-script.sh").chmod(0o700)
        executor.execute(steps[0])
        phys = discover_phys()
        steps, cleanup = command_plan(class_id, seed, directory, phys, split)
        for step in steps[1:]:
            if step.get("log") == "wpa_supplicant.log":
                scenario_start = clock_mark()
                metadata["scenario_started_at"] = scenario_start["wall_time"]
                metadata["scenario_started_monotonic_ns"] = scenario_start["monotonic_ns"]
            executor.execute(step)
        executor.healthy()
        metadata["status"] = "ok"
    except (OSError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        metadata["error"] = f"{type(error).__name__}: {error}"
    except BaseException as error:
        metadata["error"] = f"{type(error).__name__}: interrupted"
        raise
    finally:
        try:
            try:
                metadata["observation_end"], metadata["observation_window"] = executor.close_observation()
            except (OSError, RuntimeError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
                metadata["observation_end"] = executor.observation_end
                metadata["status"] = "failed"
                metadata["error"] = (metadata["error"] or "") + f"; observation close: {type(error).__name__}: {error}"
            try:
                if metadata["status"] == "ok":
                    metadata["injection_verified"], metadata["verification"] = verify_injection(
                        executor, class_id, seed, directory, parameters)
            except (OSError, RuntimeError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
                metadata["verification"].append({"check": "verification_queries", "passed": False, "detail": str(error)})
                metadata["injection_verified"] = False
            try:
                if metadata["scenario_started_at"] is not None:
                    metadata["observed"] = collect_observed(executor, class_id, seed, directory, parameters)
            except (OSError, RuntimeError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
                metadata["observed"] = {"wpa_state": None, "ipv4_lease_present": None,
                                        "ap_associated": None, "ap_authorized": None,
                                        "errors": [{"query": "collection", "error": str(error)}], "queries": []}
        finally:
            cleanup_errors = executor.cleanup(cleanup)
        if cleanup_errors:
            metadata["status"] = "failed"
            metadata["error"] = (metadata["error"] or "") + "; cleanup: " + "; ".join(cleanup_errors)
        metadata["dhcp_server_started"] = any(
            step.get("log") == "dhcp_server.log" for process, stream, step in getattr(executor, "processes", []))
        window_logs = (metadata["observation_window"] or {}).get("logs", {})
        metadata["log_scrub"] = {"rules": SCRUB_RULES, "removed_lines": {
            source: window_logs.get(source, {}).get("removed_control_lines", 0)
            for source in SCRUB_RULES["sources"]}}
        metadata["capture_health"] = check_capture_health(directory / "capture.pcap", parameters.ap_mac, binary)
        metadata["ended_at"] = utc_now()
        metadata["commands"] = executor.records
        if metadata["status"] == "ok":
            for name in ("capture.pcap", "hostapd.log", "wpa_supplicant.log", "dhcp_server.log", "dhcp_client.log"):
                if name == "dhcp_server.log" and not SCENARIOS[class_id].dhcp_server:
                    continue
                if (directory / name).stat().st_size == 0:
                    metadata["status"] = "failed"
                    metadata["error"] = f"required output is empty: {name}"
                    break
        metadata = validate_meta(metadata).model_dump(mode="json")
        (directory / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return not metadata["quarantined"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--classes", nargs="+", choices=CLASS_IDS, default=list(CLASS_IDS))
    parser.add_argument("--per-class", type=int, default=12, help="1..12 draws per class; 12 = 4 dev + 8 test")
    parser.add_argument("--split", choices=("dev", "test", "all"), default="all",
                        help="filter the selected seed prefix; default all")
    parser.add_argument("--seed-base", type=int, default=1000)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--binary", help="airtrace executable for AP beacon capture-health checks")
    args = parser.parse_args(argv)
    try:
        schedule = seed_schedule(args.seed_base, args.per_class, args.split)
    except ValueError as error:
        parser.error(str(error))
    if len(set(args.classes)) != len(args.classes):
        parser.error("duplicate classes are not allowed")
    if not schedule:
        parser.error("selected seed prefix contains no bundles for this split; increase --per-class")
    destination = args.out.resolve()
    if args.dry_run:
        print("# Exact argv plan for a fresh dedicated host; physical names are discovered from wlan*/phy80211 at runtime.")
        index = 0
        for class_id in args.classes:
            for split, seed in schedule:
                phys = [f"phy{index + offset}" for offset in range(3)]
                show_plan(class_id, split, seed, destination / bundle_id(class_id, seed), phys, args.binary)
                index += 3
        return 0
    if platform.system() != "Linux" or os.geteuid() != 0:
        parser.error("execution requires Linux and root; use --dry-run on other systems")
    if Path("/sys/module/mac80211_hwsim").exists() or list(Path("/sys/class/ieee80211").glob("*")):
        parser.error("use a dedicated host with no loaded hwsim module or existing Wi-Fi phys")
    if destination.exists() and any(destination.iterdir()):
        parser.error("output directory must be empty; existing bundles are never overwritten")
    destination.mkdir(parents=True, exist_ok=True)
    commit = git_commit()
    versions = tool_versions()
    failed = 0
    try:
        for class_id in args.classes:
            for split, seed in schedule:
                opaque_id = bundle_id(class_id, seed)
                okay = run_bundle(class_id, split, seed, destination / opaque_id, commit, versions, args.binary)
                failed += not okay
                print(f"{opaque_id}: {'ok' if okay else 'failed'}", flush=True)
    finally:
        write_manifest(destination, args.seed_base, commit)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
