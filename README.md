# airtrace

A C11 parser for classic pcap captures containing 802.11 frames, with JSONL output
and capture statistics. The parsing API uses caller-owned storage and performs no
dynamic allocation. The command-line tool, parser tests, benchmark, and fuzz target
are C. The optional fault lab and triage evaluation harness use Python.

## Build and test

Requires CMake 3.20 or later and GCC or Clang. Unity is vendored, and the sample
captures and tshark reference fixtures are checked in; normal builds and tests do
not need network access or tshark.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Use `-DCMAKE_C_COMPILER=clang` in a separate build directory to test Clang.
Every target builds as C11 with `-Wall -Wextra -Wpedantic -Werror`.
Windows users can use WSL; native MSVC support is outside v0.1.

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang -DAIRTRACE_SANITIZE=ON
cmake --build build-asan --parallel
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  ctest --test-dir build-asan --output-on-failure
```

GitHub Actions defines Ubuntu/macOS × GCC/Clang build-and-test and ASan/UBSan
matrices, plus a 60-second Clang libFuzzer smoke run on each OS. macOS jobs select
Homebrew GCC explicitly; the fuzz job uses Homebrew LLVM for libFuzzer support.

## Usage

```sh
build/airtrace parse capture.pcap
build/airtrace parse capture.pcap --jsonl > frames.jsonl
build/airtrace parse capture.pcap --stats
build/airtrace parse capture.pcap --jsonl --stats > frames.jsonl 2> summary.txt
```

JSONL is the default. `--stats` alone prints a text summary to stdout. With both
options, JSONL stays on stdout and statistics go to stderr. Diagnostics always
go to stderr. Exit status is 0 for success, 1 for an input/output/parse/capacity
error, and 2 for incorrect usage. With JSONL enabled, a rejected frame produces a
JSON error record and parsing continues; an invalid pcap record stops the reader.

For example, frame 87 of `tests/fixtures/wpa-Induction.pcap`:

```json
{"frame":87,"ts":1167891291.509261000,"rssi_dbm":null,"freq":2412,"channel":1,"type":"data","subtype":"data","type_id":2,"subtype_id":0,"addrs":["00:0d:93:82:36:3a","00:0c:41:82:b2:55","00:0c:41:82:b2:55"],"bssid":"00:0c:41:82:b2:55","ssid":null,"seq":4043,"retry":false,"protected":false,"status_code":null,"reason_code":null,"eapol_msg":1,"ie_summary":[]}
```

`ts` is epoch seconds with nine fractional digits. Missing information is `null`;
an empty SSID is `""`. SSIDs are arbitrary bytes: printable ASCII is emitted
literally, quotes/backslashes are escaped, and other bytes use `\u00xx`. Decode
these strings as byte values 0–255 when exact SSID octets matter. `addrs` follows
wire order (addr1 through addr4), rather than inferred source/destination order.
`ie_summary` preserves each IE's ID and length, including unknown and duplicate IEs.

Selected `--stats` output for `Network_Join_Nokia_Mobile.pcap`:

```text
Frames: 1180  parsed: 1180  errors: 0
Subtypes:
  0/0 assoc_req                1
  0/1 assoc_resp               1
  0/4 probe_req                9
  0/5 probe_resp               37
  0/8 beacon                   647
  0/11 auth                     2
  0/12 deauth                   1
  1/13 ack                      88
  2/0 data                     387
  2/4 null                     7
BSSIDs (last observed channel; observed RSSI):
  00:01:e3:41:bd:6e ssid="martinet3" channel=11 frames=1083 rssi=unknown
Deauth/disassoc reasons:
  deauth reason=3 count=1
4-way handshakes (messages observed across capture, including retries):
  client=00:16:bc:3d:aa:57 bssid=00:01:e3:41:bd:6e observed=1234 complete=yes counts=4,4,4,4
```

BSSID summaries retain a revealed SSID across later hidden-SSID advertisements,
show the last observed channel, and report mean/min/max RSSI when available.
Broadcast/zero BSSIDs are excluded. Handshake completeness means all four message
numbers were observed for the client/BSSID pair across the capture. It does not
verify a single exchange, replay-counter consistency, a MIC, or a password. Retries
are counted. Both sample captures lack dBm signal metadata, so RSSI is unknown.

`wpa-Induction.pcap` contains ten frames with unknown protocol versions, also
identified by tshark. Its CLI run returns 1, emits 1,093 JSONL records (1,083 parsed
frames and ten error records), and reports the complete four-message handshake.
This expected behavior is covered by the golden and CLI tests.

## Library API

```c
#include "airtrace.h"

airtrace_frame frame;
airtrace_err err = airtrace_parse_frame(bytes, length,
                                      AIRTRACE_LINKTYPE_RADIOTAP, &frame);
if (err == AIRTRACE_OK && frame.has_ssid) {
    /* frame.ssid is an array of frame.ssid_len bytes, not a C string. */
}
```

`include/airtrace.h` exposes the parser, error codes, subtype names, and output
struct. `include/airtrace_pcap.h` exposes a separate streaming reader over a
caller-owned `FILE *` and packet buffer. The reader normalizes fractional capture
timestamps to nanoseconds and accepts both byte orders of microsecond and
nanosecond pcap 2.4, with link types 105 and 127. It validates record lengths,
snaplen, and timestamp fractions. Errors clear the output struct; terminal reader
errors invalidate its file pointer. The caller still closes the original file.

The parser decodes multibyte values explicitly, never casts packet bytes to C
structs, and bounds-checks fields before reading them. Input and output must not
overlap. `airtrace_frame` contains no input pointers: IE/RSN offsets refer to the
original input buffer, which the caller must retain to inspect those payloads.
`header_len` counts MAC header bytes and excludes radiotap and data padding.

Radiotap extraction includes TSFT, Flags, Rate (500-kbit/s units), Channel
(frequency in MHz and flags), signed dBm antenna signal, and the three MCS bytes.
Presence maps, field alignment relative to the radiotap start, namespace resets,
vendor skip lengths, and TLVs are bounded by `it_len`. Other known fixed-layout
fields are skipped using their standard sizes/alignments. New fields numbered
32 and above use standard TLVs. Unknown bitmap layouts return `UNSUPPORTED`;
their byte offsets cannot safely be inferred. Repeated radiotap values use the
last value; extracted singleton IEs use the first occurrence.

Management parsing covers association/reassociation requests and responses,
probe requests/responses, beacons, disassociation, authentication, and
deauthentication, with their fixed fields. It extracts SSID, Supported Rates,
DS channel, HT/VHT capabilities, and the bounded RSN payload. HT/VHT payloads are
copied; RSN internals are opaque. A DS channel IE takes precedence over a channel
derived from radio frequency. Authentication algorithms beyond Open/Shared/FT
retain fixed fields and leave algorithm-specific payloads opaque.

Data parsing handles four-address and QoS headers, optional HT Control, and
radiotap data padding. LLC/SNAP EAPOL-Key detection validates the complete
descriptor and key-data length before classifying pairwise messages. Group-key,
error, request, and SMK messages are not counted as four-way handshakes. Legacy
WPA message 4 without the Secure bit is distinguished using its empty key data.

## Tests and fixtures

Unity tests use hand-built arrays to exercise protocol fields, all supported
management subtypes, truncation, capacities, alignment, namespaces, four-address
QoS frames, EAPOL messages, FCS handling, and all four pcap magic/endian variants.
Golden tests compare capture fields against checked-in `tshark -T fields` output.
The CLI test parses every JSONL record and checks summaries and error behavior.

See [fixture provenance](tests/fixtures/README.md) for capture URLs, SHA-256 hashes,
tshark version, selected fields, and commands to regenerate reference data.
Unity's upstream license is retained in [third_party/unity/LICENSE.txt](third_party/unity/LICENSE.txt).
Third-party attributions are collected in [NOTICE](NOTICE).

## Fuzzing

```sh
cmake -S . -B build-fuzz -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo -DAIRTRACE_FUZZ=ON -DBUILD_TESTING=OFF
cmake --build build-fuzz --parallel
mkdir -p fuzz/corpus fuzz/artifacts
build-fuzz/airtrace_seed tests/fixtures/wpa-Induction.pcap fuzz/corpus induction
build-fuzz/airtrace_seed tests/fixtures/Network_Join_Nokia_Mobile.pcap fuzz/corpus nokia
build-fuzz/airtrace_fuzz fuzz/corpus -max_total_time=3600 -timeout=10 \
  -max_len=65536 -artifact_prefix=fuzz/artifacts/ -print_final_stats=1
```

This runs for approximately one hour; use `-max_total_time=60` for the CI smoke
duration. The C seed extractor produces 2,273 inputs from the two captures. Each
input has one prefix byte selecting raw 802.11 (0) or radiotap (1), followed by the
captured frame. A separate parser library is instrumented with
`-fsanitize=fuzzer-no-link,address,undefined`; the fuzz executable links with
`-fsanitize=fuzzer,address,undefined`. Assertions check output capacities, IE
bounds, and cleared outputs on errors. Fuzz artifacts and evolving corpus files
are ignored by Git. On macOS use Homebrew LLVM's `clang` for libFuzzer.

## Benchmark

```sh
build/airtrace_bench tests/fixtures/wpa-Induction.pcap 10000
build/airtrace_bench tests/fixtures/Network_Join_Nokia_Mobile.pcap 10000
```

The optional argument is the number of passes. The benchmark loads the capture
once, warms the parser, and times only repeated parsing. It prints CPU model,
frame count, passes, accepted/rejected totals, elapsed time, frames/s, and a
checksum. Report the compiler, build type, capture, and passes with any result.
Frames/s includes rejected frames; use the Nokia capture for an all-success run.
Allocation during benchmark setup is outside the parsing path and timed loop.

## Triage and evaluation

The v0.2 harness wraps the unchanged v0.1.0 parser:

1. `lab/` injects nine Wi-Fi scenarios into Linux mac80211_hwsim; labels come from the injected class.
2. Opaque bundle IDs hold the pcap and ordered daemon logs; metadata records injection checks, quarantine and environment.
3. `triage/data.py` runs airtrace; the default client view exposes capture, station and DHCP-client observations through redaction.
4. Rules, raw-log LLM, and tool-using LLM arms share the view and diagnosis schema; quotes are checked against visible sources.
5. Evaluation reports paired differences, exact McNemar tests, bootstrap/binomial intervals, exclusions, citations, usage and estimated costs.

Generate the 108-bundle dataset with the manual **Wi-Fi fault lab** workflow in
[lab.yml](.github/workflows/lab.yml), then download its artifact. It uses
`ubuntu-22.04`, 4 dev runs and 8 test runs per class, with held-out seeds and parameter range.
Dev uses channels 1–6 and delays 0.2–1.2 s; test uses channels 7–11 and delays 1.5–3.0 s.
The workflow accepts `split=dev`, `test`, or `all` (default) and allows 330 minutes.
When checked in September 2026, `mac80211_hwsim` was unavailable on WSL2 and on
`ubuntu-24.04` runners, so the lab does not run there.
See [lab/README.md](lab/README.md) for root requirements, dry-run commands,
failure recording, and the dev-only observation table.

Python >=3.10 with `pytest`, `pydantic>=2`, and `httpx` is required. Point
`AIRTRACE_BIN` at a built CLI (or pass `--airtrace` to evaluation). For example:

```sh
export AIRTRACE_BIN="$PWD/build/airtrace"
python -m pytest tests/triage tests/lab -q
python -m lab.observe --dataset datasets/wifi
python -m triage.eval --dataset datasets/wifi --split dev --arms rules --out results/dev-rules
```

On native Windows, build with
`gcc -std=c11 -O2 -Iinclude src/airtrace.c src/pcap.c src/main.c -o .local/airtrace.exe`
and set `$env:AIRTRACE_BIN` to its absolute path. Create `.local` first.
Tests generate small byte fixtures under ignored `.local`; no model service is
needed. `AIRTRACE_DATASET` enables the additional generated-dataset checks.

For model runs, review [models.json](models.json), remove unused entries, and
explicitly select settings. [models.example.json](models.example.json) documents the format.
The `_comment` fields are documentation in valid JSON. A local server needs no
API key; hosted entries name an environment variable, never a stored key.
These commands make requests to the configured service:

```sh
python -m triage.eval --dataset datasets/wifi --split dev --arms rules llm_raw llm_tools --models models.json --out results/dev-all
python -m triage.leakprobe datasets/wifi
# Review dev observations and finish rules/settings before freezing.
python -m triage.freeze --dataset datasets/wifi --models models.json
python -m triage.eval --dataset datasets/wifi --split test --arms rules llm_raw llm_tools --models models.json --out results/test-all
```

Freezing records test-manifest, rules, instruction-file, model-configuration,
and working-source hashes in `triage/FROZEN.json`; test evaluation refuses any
change. Every result records those inputs and the Git commit. The freeze file
is created exclusively and is ignored by Git; retain it with the experiment
results. Dev runs are unrestricted. Changing the freeze after inspecting test
results does not create a new independent evaluation with held-out seeds and parameter range.
Frozen settings also include the view, raw budget, model output/context limits,
citation-rules version, control-echo scrub rules and causal label map.

`--view client` is the default and primary result: capture, `wpa_supplicant.log`,
and `dhcp_client.log`. `--view full` additionally allows AP and DHCP-server logs
and is supplementary. Each arm, tool, citation checker and redaction pass obeys
this boundary; use the same view when freezing and evaluating.

The raw-log budget defaults to 48,000 characters (`--raw-char-budget`). Each
source keeps complete numbered lines from its first 15% and last 85% allocation,
with an omitted-line marker and exact trimming records. No daemon output is
invented for missing services. The harness uniformly removes control-command
echo blocks and records the scrub in metadata, outside the model view.

Before using Ollama, start its server with `OLLAMA_CONTEXT_LENGTH=32768`, or
set `num_ctx 32768` in a Modelfile. Its compatible endpoint cannot set this
per request. The configured context must match the server. Other context values
in the configuration are local planning budgets, not verified provider limits.
Preflight checks every eligible bundle before constructing clients, using a
conservative serialized-byte estimate plus output/repair reserves. A full
48,000-character input may be rejected at 32,768 context; reduce the raw budget
uniformly and freeze that choice, or increase both server and declared context.
`max_tokens` defaults to 4,096; gpt-oss uses 8,192 including reasoning tokens.
`finish_reason=length` is reported as `TRUNCATED` and excluded from accuracy,
not counted as a schema failure. Prompt usage within 2% of the declared context
raises `truncation_suspected`; that heuristic is not proof of truncation.

| Arm | Real dev results | Real results with held-out seeds and parameter range |
| --- | --- | --- |
| Rules (currently an `unknown` placeholder) | not yet run | not yet run |
| LLM, raw logs | not yet run | not yet run |
| LLM, bounded tools | not yet run | not yet run |

No empirical rules have been authored: `triage/rules.py` deliberately returns
`unknown` until the dev split has been observed. No real lab or model accuracy
result is claimed. Synthetic fixtures and scripted responses test plumbing,
not diagnostic skill. The raw arm sees fixed-budget, numbered logs; the tool arm
can inspect frames and logs. Their difference therefore includes access to
capture evidence, not just a different interaction style.

This lab models software protocol behavior, not RF propagation or physical
drivers/firmware, and uses one kernel/hostapd environment. An injected fault
does not guarantee a particular observable status/reason signature. Failed
runs and unsuccessful injection/capture checks remain on disk in quarantine,
with exclusion counts and reasons in the manifest and reports. No labels change.
Harness checks establish the configured intervention and available acknowledgements;
they do not guarantee a particular client-visible effect. A citation passing
means its quotation exists, not that it proves the root cause. Bootstrap
intervals cover bundle sampling, not hardware diversity or repeated model
draws. Logs and traces can still contain sensitive information beyond MACs,
SSIDs and configured passphrases; HMAC pseudonymisation is not anonymisation.

Evaluation writes `metrics.json`, `per_bundle.jsonl`, `report.md`, `audit_sample.csv`, and an
append-only `trace.jsonl` for model calls. Traces retain full redacted requests,
tool definitions, replies, resolved model identifiers, usage and retry details
for replay without another model request. The per-run redaction key is not
saved. Unsupported code lookups return `unknown` rather than guessing.
Automatic rule/fallback evidence is excluded from citation metrics. Model quotes
must resolve to a complete frame JSON member or a log quote containing at least
12 non-whitespace characters; repetition on more than three locations is reported
separately as ambiguity. Fill the audit CSV's empty `supports_diagnosis` column
to assess causal support manually.

The leak probe fits a deliberately naive classifier using dev-only metadata
features and reports test accuracy, a majority baseline and a shuffled-label
control. A gain greater than 20 percentage points is flagged for review; genuine
fault effects can also change log sizes or duration, so this is not proof of
contamination. No real dataset or model evaluation has been run here.

## Limitations

- No pcapng, decryption, A-MSDU/A-MPDU disaggregation, or fragment reassembly.
- Protected, fragmented, and A-MSDU frames expose headers; their payloads remain
  opaque. Capture records must contain individual MAC frames, not raw aggregates.
- Radiotap Flags determines whether four FCS bytes are removed. CRC validation is
  not performed. Raw linktype 105 is treated as having no FCS; pcap linktype words
  carrying additional FCS metadata are rejected rather than guessed.
- Advanced control/extension layouts and action bodies are outside scope.
  Supported control frames expose their MAC header, not BlockAck internals.
- Unknown IEs are bounds-checked and retained as ID/length/offset entries. The
  fixed table holds 128 IEs; excess entries return `AIRTRACE_ERR_CAPACITY`.
- The CLI accepts packets up to 1 MiB and tracks up to 1,024 BSSIDs and 4,096
  client/BSSID pairs. Summary-table overflow is reported and returns failure.
- The benchmark and seed extractor accept capture snaplen values up to 16 MiB.
- This is an offline parser. Handshake observation does not establish successful
  authentication, key validity, or traffic decryptability.

Protocol references: [Radiotap definitions](https://www.radiotap.org/fields/defined),
[Radiotap TLVs](https://www.radiotap.org/fields/TLV.html),
[pcap savefile format](https://www.tcpdump.org/manpages/pcap-savefile.5.html), and
[Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures#Wifi_.2F_Wireless_LAN_captures_.2F_802.11).
