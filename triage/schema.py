"""One constrained output format shared by every diagnosis arm."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


CLASS_IDS = (
    "ok", "wrong_passphrase", "akm_mismatch", "pmf_required_unsupported",
    "mac_denied", "ap_full", "dhcp_no_server", "ap_deauth", "ssid_not_found",
)
RootCause = Literal["ok", "wrong_passphrase", "akm_mismatch",
                    "pmf_required_unsupported", "mac_denied", "ap_full",
                    "dhcp_no_server", "ap_deauth", "ssid_not_found", "unknown"]


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source: Literal["frame", "hostapd", "wpa_supplicant", "dhcp_server", "dhcp_client"]
    ref: int = Field(ge=1)
    quote: str = Field(min_length=1, max_length=2000)
    auto: bool = False


class Diagnosis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    root_cause: RootCause
    evidence: list[Evidence] = Field(min_length=1, max_length=6)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    fix: str = Field(max_length=300)


JSON_SCHEMA = Diagnosis.model_json_schema()


def unknown(view, fix: str = "Insufficient evidence to diagnose this bundle.") -> Diagnosis:
    import json
    from triage.data import render_frame

    for source, lines in view.logs.items():
        for number, line in enumerate(lines, 1):
            quote = line[:2000]
            if len("".join(quote.split())) >= 12:
                evidence = Evidence(source=source, ref=number, quote=quote, auto=True)
                return Diagnosis(root_cause="unknown", evidence=[evidence],
                                 confidence=0.0, fix=fix[:300])
    for number, frame in view.frames.items():
        quote = render_frame(frame)
        if len(quote) > 2000:
            members = [json.dumps({key: value}, sort_keys=True, ensure_ascii=True)[1:-1]
                       for key, value in sorted(frame.items())]
            quote = next((member for member in members if len(member) <= 2000), "")
        if quote and frame:
            evidence = Evidence(source="frame", ref=number, quote=quote, auto=True)
            return Diagnosis(root_cause="unknown", evidence=[evidence], confidence=0.0,
                             fix=fix[:300])
    raise ValueError("Cannot cite a bundle without a complete frame member or a sufficiently long log line")


if __name__ == "__main__":
    import json
    print(json.dumps(JSON_SCHEMA, indent=2))
