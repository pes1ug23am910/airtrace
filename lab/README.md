# Wi-Fi fault lab

This generator exercises a real Linux mac80211/hostapd/wpa_supplicant stack using
`mac80211_hwsim`. The label is the selected injection class, by construction;
packet observations never change it. A failed setup or unmet required precondition
is saved as `status: failed` with its error. Failed injection verification or capture
health also quarantines a bundle: it remains on disk and in the manifest, is counted
in reports, and is excluded from diagnosis scoring. Dataset checks expose quarantines.

The nine classes are `ok`, `wrong_passphrase`, `akm_mismatch`,
`pmf_required_unsupported`, `mac_denied`, `ap_full`, `dhcp_no_server`, `ap_deauth`,
and `ssid_not_found`. `scenarios.py` contains their configuration and actions.
Each seed independently chooses SSIDs, passwords, locally administered unicast
MAC addresses, a channel from 1â€“11, and startup delays. No 5 GHz channels are used.
Both the on-air and alternate SSID use the same prefix, length, and alphabet.
Bundle directories use 12-character hashes of the injection class and seed;
the label is stored only in `meta.json`, never in generated path names.

Use the manual **Wi-Fi fault lab** GitHub Actions workflow (`lab.yml`) on
`ubuntu-22.04`. It builds airtrace, installs the lab utilities, generates the
selected split, validates it, and uploads all outputs even when a run fails. Its
optional `split` input is `dev`, `test`, or `all` (default); its timeout is 330 minutes. The workflow
has not been executed for this addition. When checked in September 2026, Ubuntu 24.04
hosted runners and WSL2 did not supply this module.

On a dedicated Linux machine with the dependencies installed:

```sh
sudo python -m lab.run_lab --binary build/airtrace --classes ok wrong_passphrase --per-class 12 --seed-base 1000 --out .local/dataset
AIRTRACE_BIN=build/airtrace python -m pytest tests/lab --lab-dataset .local/dataset
AIRTRACE_BIN=build/airtrace python -m lab.observe --dataset .local/dataset
```

Omitting `--classes` selects all nine. `--per-class 12` means four dev seeds
`S..S+3` and eight test seeds `S+100..S+107`: 108 bundles in one job. Values 1â€“11
select a prefix for setup smoke checks; they are incomplete datasets and should
not be described as the 108-bundle experiment. `--split dev` or `--split test`
filters this prefix; with the default `--per-class 12`, these produce 36 or 72
bundles respectively. Use `--split dev` to inspect development data first.
An empty selection is rejected. Existing bundles are never
overwritten. The output should be outside tracked source files.

```sh
python -m lab.run_lab --per-class 1 --seed-base 1000 --out .local/dataset --dry-run
```

The dry run executes no commands and writes no files. It prints generated config
contents, the argv plan, polling conditions, timeouts, and cleanup. Physical names
shown assume a fresh dedicated host; execution discovers each wlan interface's
actual phy name because kernel wiphy indices increase across module reloads.

Three radios are used, with AP, test station, and optional occupying station in
separate network namespaces. DHCP packets must traverse the simulated radio link.
There is no bridge or veth shortcut. The BusyBox udhcpc script configures only the station
address and never rewrites the host resolver configuration. `ap_full` waits until
the occupying station completes WPA and hostapd reports it authorized before
starting the tested station. `ap_deauth` requires a completed connection before
issuing the deauthentication. `ok` requires WPA completion and an assigned DHCP
address; `dhcp_no_server` requires WPA completion. These are injection/control
preconditions, not class-specific packet-signature assumptions.

Every run observes the tested station for at least 30 seconds. Setup and polling
are bounded, each background process also runs under GNU `timeout`, and a finally
block terminates process groups before deleting owned namespaces and unloading
the module. The generator refuses a host with existing Wi-Fi phys or a loaded
hwsim module. Use an otherwise idle disposable host.

A bundle includes the capture, the four model-visible logs, metadata, generated
configs, control-process logs, and any DHCP lease files. Logs remain plain text
in original order; dnsmasq writes `dhcp_server.log`, and udhcpc writes
`dhcp_client.log`. When the server never starts, its log is empty: the harness
adds no placeholder or other text to model-visible logs. hostapd and both stations
run at `-d -t` (DEBUG, not MSGDUMP). A uniform build-time scrub removes `RX ctrl_iface`
and `CTRL_IFACE:` command-echo lines and indented continuation lines from hostapd
and tested-station logs in every class. Other retained lines remain in original order.
The scrub rule and per-source removed-line counts are recorded only in metadata and
the manifest. The generated configurations and control-query outputs never enter
an arm's observation view. Metadata
records the injected label, parameters, seed/split, timestamps, kernel, tool
versions, git commit, command outcomes, and setup failures. `manifest.json`
hashes every regular bundle file and lists opaque identifiers, splits, seeds,
quarantine counts/reasons, verification flags, capture health, and scrub provenance.
Every bundle entry also copies kernel release and tool versions: hostapd,
wpa_supplicant, dnsmasq, BusyBox udhcpc, tcpdump, Python, and tshark if available
(absence is recorded explicitly).
Scoring and observation read labels from bundle metadata. Validation rejects
changed or unlisted files and bundle directory names that do not match their opaque id.
The generator commit identifies committed source; use a clean checkout when
producing a dataset intended for a reproducible evaluation.

Injection checks are harness-side control/status queries and process-state checks,
not patterns matched in the model-visible logs. Every class requires live AP/station
processes, an enabled AP, matching configured SSIDs from control queries, the station
PMF setting, and a responsive station control interface. The server must be live
except in the no-server class. The class-specific checks are:

| Class | Additional verification |
| --- | --- |
| `ok` | Station status is COMPLETED and its namespace has the DHCP subnet address. |
| `wrong_passphrase` | Running processes consumed files with the generated unequal AP/station credentials. |
| `akm_mismatch` | AP GET_CONFIG reports SAE and the running station consumed PSK-only configuration. |
| `pmf_required_unsupported` | Running AP consumed `ieee80211w=2`; station GET_NETWORK reports 0. |
| `mac_denied` | AP DENY_ACL SHOW includes the tested station address. |
| `ap_full` | Running AP consumed `max_num_sta=1`; occupant STA query reports AUTHORIZED. |
| `dhcp_no_server` | No server process was launched in the new AP namespace; station status is COMPLETED. |
| `ap_deauth` | A station COMPLETED status query precedes a successful AP deauthenticate acknowledgement. |
| `ssid_not_found` | AP and station control queries report different generated SSIDs. |

The hostapd control API does not expose all loaded settings. For password, AP PMF,
and station limit, the check combines the exact consumed configuration with live,
responsive daemon state; it does not independently prove the configured setting's
internal application or a client-visible failure. An action acknowledgement likewise
does not prove the client processed the action. These limits are stored in the check
details. Each completed capture is parsed with airtrace after shutdown and must
contain at least one beacon whose BSSID matches the configured AP. Missing/empty
captures, parser failures, or missing AP beacons fail capture health.

`observe.py` reads only the dev split and reports quarantined counts. Its table reports observed status/reason
codes, whether airtrace saw all four EAPOL message numbers for a client/BSSID
pair, and DHCP-client lease log entries, followed by numbered status/reason log
lines. Four observed messages do not prove a valid single exchange, matching
replay counters, password validity, or a verified MIC. No class-specific packet
signature assertions or trained baseline rules have been written yet.

This lab does not simulate RF propagation, distance, interference, real hardware
drivers, firmware, roaming, or all real-world causes. A single job fixes a single
kernel and tool-version environment. Held-out seeds and parameter range vary settings, not independent
physical environments. Successful injection is not a guarantee that every fault
produces a distinguishable capture or log signature. Linux execution remains to
be verified; local unit tests cover rendering, planning, metadata, and integrity.
