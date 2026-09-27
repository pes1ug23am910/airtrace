"""A synchronous Chat Completions client; no provider SDK is required."""

import copy
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from triage.trace import canonical, fingerprint


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(min_length=1)
    base_url: str
    model: str = Field(min_length=1)
    api_key_env: str = ""
    supports_tools: bool = False
    rpm: float = Field(default=30, gt=0)
    supports_seed: bool = False
    seed: int = 0
    max_tokens: int = Field(default=4096, ge=1)
    context_length: int = Field(default=131072, ge=1)
    timeout: float = Field(default=60, gt=0)
    retries: int = Field(default=2, ge=0, le=5)
    input_price_inr_per_million: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    output_price_inr_per_million: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    cached_input_price_inr_per_million: float | None = Field(default=None, ge=0, allow_inf_nan=False)

    @field_validator("base_url")
    @classmethod
    def plain_url(cls, value):
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must be an HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain credentials, a query, or a fragment")
        return value.rstrip("/")


def pricing_details(config):
    """Configured prices describe an estimate, not a provider billing statement."""
    return {
        "currency": "INR", "unit": "per million tokens",
        "input_price_inr_per_million": config.input_price_inr_per_million,
        "output_price_inr_per_million": config.output_price_inr_per_million,
        "cached_input_price_inr_per_million": config.cached_input_price_inr_per_million,
        "assumptions": [
            "Prompt tokens include cached input; completion tokens include reasoning.",
            "Absent cached-token counts are treated as zero.",
            "Missing usage or required prices leaves cost unknown, including null free-tier prices.",
            "Estimates cover returned usage only; retries without usage may have unreported cost.",
        ],
    }


def estimate_cost(config, usage):
    """Return INR cost from reported usage, without counting reasoning tokens twice."""
    details = {"status": "missing_usage", "prompt_tokens": None,
               "completion_tokens": None, "cached_tokens": None,
               "cached_tokens_reported": False}
    if not isinstance(usage, dict):
        return None, details
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    details["prompt_tokens"] = prompt
    details["completion_tokens"] = completion
    for count in (prompt, completion):
        if type(count) is not int or count < 0:
            return None, details
    prompt_details = usage.get("prompt_tokens_details") or {}
    if not isinstance(prompt_details, dict):
        details["status"] = "invalid_cached_usage"
        return None, details
    cached = prompt_details.get("cached_tokens", 0)
    details["cached_tokens"] = cached
    details["cached_tokens_reported"] = "cached_tokens" in prompt_details
    if type(cached) is not int or not 0 <= cached <= prompt:
        details["status"] = "invalid_cached_usage"
        return None, details
    input_rate = config.input_price_inr_per_million
    output_rate = config.output_price_inr_per_million
    cached_rate = config.cached_input_price_inr_per_million
    if input_rate is None or output_rate is None or (cached and cached_rate is None):
        details["status"] = "missing_price"
        return None, details
    cost = (prompt - cached) * input_rate + completion * output_rate
    if cached:
        cost += cached * cached_rate
    details["status"] = "estimated_from_returned_usage"
    return cost / 1_000_000, details


@dataclass
class Completion:
    message: dict | None
    record: dict
    error: str | None = None


class ContextLimitError(ValueError):
    """The declared local context budget cannot hold the planned request."""


def estimate_prompt_tokens(messages, tools=None):
    """Conservative planning estimate: UTF-8 bytes plus message framing overhead.

    This deliberately avoids an unavailable provider-specific tokenizer. It can
    reject text that a provider would fit; it must not silently drop observations.
    Provider token accounting and server configuration still require verification.
    """
    text = canonical({"messages": messages, "tools": tools or []})
    return len(text.encode("utf-8")) + 32 * len(messages) + 256


def check_context(config, messages, tools=None):
    estimate = estimate_prompt_tokens(messages, tools)
    if estimate + config.max_tokens > config.context_length:
        raise ContextLimitError(
            f"{config.name}: estimated prompt {estimate} plus output reserve "
            f"{config.max_tokens} exceeds declared context_length {config.context_length}")
    return estimate


def redact_response_body(text, key):
    """Remove credential echoes, including JSON escapes, before parsing or tracing.

    Ordinary responses retain their exact body. If sanitization is necessary,
    the JSON envelope is serialized again so replacements cannot break quoting.
    Nested JSON strings and provider-defined fields receive the same treatment.
    """
    if not key:
        return text
    pieces = []
    for character in key:
        alternatives = [re.escape(character)]
        escaped = json.dumps(character, ensure_ascii=True)[1:-1]
        if escaped != character:
            alternatives.append(re.escape(escaped))
        if ord(character) <= 0xFFFF:
            unicode_escape = "\\u" + format(ord(character), "04x")
            alternatives.append("(?i:" + re.escape(unicode_escape) + ")")
        pieces.append("(?:" + "|".join(alternatives) + ")")
    encoded_key = re.compile("".join(pieces))

    def scrub(value):
        if isinstance(value, str):
            # Tool arguments and final answers are JSON stored inside JSON
            # strings. Inspect those layers too, while retaining ordinary text.
            try:
                nested = json.loads(value)
            except (ValueError, TypeError):
                nested = None
            if nested is not None:
                sanitized_nested = scrub(nested)
                if sanitized_nested != nested:
                    return json.dumps(sanitized_nested, ensure_ascii=True)
            return encoded_key.sub("[REDACTED CREDENTIAL]", value)
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, dict):
            return {scrub(name): scrub(item) for name, item in value.items()}
        return value

    try:
        decoded = json.loads(text)
    except (ValueError, TypeError):
        return scrub(text)
    sanitized = scrub(decoded)
    if sanitized == decoded:
        return text
    return json.dumps(sanitized, ensure_ascii=True)


class ChatClient:
    def __init__(self, config, transport=None, sleep=time.sleep, monotonic=time.monotonic):
        self.config = config
        self.sleep = sleep
        self.monotonic = monotonic
        self.next_request = 0.0
        self.http = httpx.Client(timeout=config.timeout, transport=transport,
                                 follow_redirects=False)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.http.close()

    def _limit(self):
        delay = self.next_request - self.monotonic()
        if delay > 0:
            self.sleep(delay)
        self.next_request = self.monotonic() + 60.0 / self.config.rpm

    def complete(self, messages, tools=None, *, run_id="", bundle_id="", arm="",
                 call_index=0, prompt_hashes=None, view="client"):
        config = self.config
        estimated_tokens = check_context(config, messages, tools)
        parameters = {"temperature": 0, "max_tokens": config.max_tokens}
        if config.supports_seed:
            parameters["seed"] = config.seed
        payload = {"model": config.model, "messages": copy.deepcopy(messages), **parameters}
        if tools:
            payload["tools"] = copy.deepcopy(tools)
        definitions = payload.get("tools", [])
        record = {
            "run_id": run_id, "bundle_id": bundle_id, "arm": arm, "view": view,
            "call_index": call_index, "timestamp": datetime.now(timezone.utc).isoformat(),
            "messages": payload["messages"], "messages_sha256": fingerprint(payload["messages"]),
            "messages_text": canonical(payload["messages"]),
            "tool_definitions": definitions, "tool_definitions_sha256": fingerprint(definitions),
            "tool_definitions_text": canonical(definitions),
            "request": payload, "request_text": canonical(payload),
            "request_sha256": fingerprint(payload), "prompt_hashes": prompt_hashes or {},
            "requested_model": config.model, "resolved_model": None,
            "base_url_host": urlsplit(config.base_url).hostname,
            "parameters": parameters, "latency_ms": 0.0,
            "tokens": {"prompt": None, "completion": None, "total": None},
            "finish_reason": None, "retry_count": 0, "retry_errors": [],
            "attempts": [], "raw_response_body": None, "validation_passed": False,
            "validation_error": None, "usage": None, "cost_inr": None,
            "pricing": pricing_details(config),
            "cost_details": {"status": "missing_usage"},
            "context_length": config.context_length,
            "estimated_prompt_tokens": estimated_tokens,
            "truncation_suspected": False,
        }
        key = os.environ.get(config.api_key_env, "") if config.api_key_env else ""

        started = self.monotonic()
        if config.api_key_env and not key:
            error = "configured API key environment variable is unset"
            record["validation_error"] = error
            return Completion(None, record, error)
        headers = {"Authorization": "Bearer " + key} if key else {}
        error = None
        raw = None
        for attempt in range(config.retries + 1):
            self._limit()
            retryable = False
            try:
                response = self.http.post(config.base_url + "/chat/completions",
                                          headers=headers, json=payload)
                raw = redact_response_body(response.text, key)
                record["raw_response_body"] = raw
                attempt_record = {"index": attempt, "status": response.status_code,
                                  "raw_response_body": raw, "error": None}
                if response.status_code < 200 or response.status_code >= 300:
                    error = "HTTP " + str(response.status_code)
                    retryable = response.status_code == 429 or response.status_code >= 500
                else:
                    error = None
            except httpx.TimeoutException:
                error = "request timed out"
                record["raw_response_body"] = None
                retryable = True
                attempt_record = {"index": attempt, "status": None,
                                  "raw_response_body": None, "error": error}
            except httpx.RequestError as exc:
                # Exception messages can contain URLs or request headers.
                error = "request failed: " + type(exc).__name__
                record["raw_response_body"] = None
                attempt_record = {"index": attempt, "status": None,
                                  "raw_response_body": None, "error": error}
            attempt_record["error"] = error
            record["attempts"].append(attempt_record)
            if error is None:
                break
            if not retryable or attempt == config.retries:
                break
            record["retry_errors"].append({"attempt": attempt, "error": error})
            record["retry_count"] += 1
            self.sleep(2 ** attempt)
        record["latency_ms"] = (self.monotonic() - started) * 1000
        message = None
        if error is None:
            try:
                body = json.loads(raw)
                if not isinstance(body, dict):
                    raise ValueError("response is not an object")
                record["resolved_model"] = body.get("model")
                usage = body.get("usage")
                record["usage"] = copy.deepcopy(usage)
                record["cost_inr"], record["cost_details"] = estimate_cost(config, usage)
                choice = body["choices"][0]
                if not isinstance(choice, dict):
                    raise ValueError("choice is not an object")
                record["finish_reason"] = choice.get("finish_reason")
                message = choice["message"]
                if not isinstance(message, dict):
                    raise ValueError("message is not an object")
                usage = usage or {}
                if not isinstance(usage, dict):
                    raise ValueError("usage is not an object")
                for short, long in [("prompt", "prompt_tokens"),
                                    ("completion", "completion_tokens"),
                                    ("total", "total_tokens")]:
                    count = usage.get(long)
                    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
                        record["tokens"][short] = count
                prompt_count = record["tokens"]["prompt"]
                record["truncation_suspected"] = (
                    prompt_count is not None and prompt_count >= 0.98 * config.context_length)
            except (ValueError, KeyError, IndexError, TypeError):
                error = "invalid Chat Completions response envelope"
        record["validation_error"] = error
        return Completion(message, record, error)
