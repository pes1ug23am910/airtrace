"""No per-class packet signatures are asserted before dev observations exist."""

from lab.manifest import validate_meta
from triage.data import load_bundle


def test_generated_bundle(lab_bundle_path):
    bundle = load_bundle(lab_bundle_path)
    meta = validate_meta(bundle.meta)
    assert meta.status == "ok", meta.error
    assert not meta.quarantined, meta.quarantine_reasons
    assert meta.injection_verified
    assert meta.capture_health["healthy"] and meta.capture_health["ap_beacons"] >= 1
    assert bundle.frames, "capture contains no frame records"
    for source, lines in bundle.logs.items():
        if source == "dhcp_server" and meta.label == "dhcp_no_server":
            assert not lines, "an absent server must not produce a log"
        else:
            assert lines and any(line.strip() for line in lines), source
    assert "Pcap record after frame" not in bundle.diagnostics
    # Frame-level unsupported records are kept and reported, not mistaken for bad pcap.
    if bundle.returncode:
        assert bundle.returncode == 1
        assert any("error" in frame for frame in bundle.frames.values()), bundle.diagnostics
        assert "capacity exceeded" not in bundle.diagnostics
