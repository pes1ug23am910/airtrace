"""Run each comparison arm against the same redacted observations."""

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from triage.data import View
from triage.llm import ContextLimitError, check_context, estimate_prompt_tokens
from triage.schema import Diagnosis, unknown
from triage.tools import Toolbox


@dataclass
class ArmResult:
    diagnosis: Diagnosis
    schema_failure: bool = False
    latency_ms: float = 0.0
    tokens: dict = field(default_factory=lambda: {"prompt": 0, "completion": 0, "total": 0})
    trimming: dict = field(default_factory=dict)
    prompt_hashes: dict = field(default_factory=dict)
    error: str | None = None
    cost_inr: float | None = 0.0
    pricing: dict = field(default_factory=dict)
    outcome: str = "DIAGNOSED"
    finish_reason: str | None = None
    truncation_suspected: bool = False
    context_plan: dict = field(default_factory=dict)


REPAIR_RESERVE = 8192
TOOL_HISTORY_BUDGET = 16000


def prompts(arm):
    directory = Path(__file__).parent / "prompts"
    texts = []
    hashes = {}
    for name in ["common.txt", arm + ".txt"]:
        content = (directory / name).read_bytes()
        texts.append(content.decode("utf-8"))
        hashes[name] = hashlib.sha256(content).hexdigest()
    schema = json.dumps(Diagnosis.model_json_schema(), sort_keys=True)
    return "\n".join(texts) + "\nDiagnosis schema:\n" + schema, hashes


def raw_logs(view, budget=48000):
    """Keep complete numbered lines: 15% of retained space at the head, 85% at the tail."""
    if budget < 300:
        raise ValueError("raw log character budget must be at least 300")
    chunks = []
    trimming = {}
    sources = view.allowed_sources
    for index, source in enumerate(sources):
        allocation = budget // len(sources)
        if index < budget % len(sources):
            allocation += 1
        lines = view.logs[source]
        heading = source + ":\n"
        numbered = [str(number) + ": " + line + "\n"
                    for number, line in enumerate(lines, 1)]
        original_chars = len(heading) + sum(len(line) for line in numbered)
        head_numbers = list(range(1, len(lines) + 1))
        tail_numbers = []
        marker = ""
        if original_chars > allocation:
            # Reserve enough room even when every line is omitted. Keeping whole
            # lines prevents a trimmed quotation from losing its original number.
            reserve = len("[... " + str(len(lines)) + " lines omitted ...]\n")
            available = max(0, allocation - len(heading) - reserve)
            head_budget = int(available * 0.15)
            tail_budget = available - head_budget
            head_numbers = []
            head_size = 0
            for number, line in enumerate(numbered, 1):
                if head_size + len(line) > head_budget:
                    break
                head_numbers.append(number)
                head_size += len(line)
            tail_size = 0
            for number in range(len(lines), len(head_numbers), -1):
                if tail_size + len(numbered[number - 1]) > tail_budget:
                    break
                tail_numbers.append(number)
                tail_size += len(numbered[number - 1])
            tail_numbers.reverse()
            omitted = len(lines) - len(head_numbers) - len(tail_numbers)
            marker = "[... " + str(omitted) + " lines omitted ...]\n"
        included = head_numbers + tail_numbers
        body = heading + "".join(numbered[n - 1] for n in head_numbers)
        body += marker + "".join(numbered[n - 1] for n in tail_numbers)
        trimming[source] = {
            "total_lines": len(lines), "included_lines": len(included),
            "included_line_numbers": included,
            "head_line_numbers": head_numbers, "tail_line_numbers": tail_numbers,
            "omitted_lines": len(lines) - len(included),
            "partial_last_line": False,
            "original_chars": original_chars, "included_chars": len(body),
            "allocated_chars": allocation, "omission_marker": marker.rstrip("\n"),
            "trimmed": original_chars > allocation,
        }
        chunks.append(body)
    return "".join(chunks), trimming


def _tool_results(message, toolbox):
    calls = message.get("tool_calls")
    if not isinstance(calls, list) or not calls or len(calls) > 6:
        raise ValueError("a tool round must contain between one and six calls")
    assistant = {"role": "assistant", "content": message.get("content"), "tool_calls": calls}
    responses = []
    seen = set()
    for call in calls:
        if not isinstance(call, dict) or not isinstance(call.get("id"), str):
            raise ValueError("tool call requires a string id")
        if call["id"] in seen:
            raise ValueError("tool call ids must be unique within a round")
        seen.add(call["id"])
        try:
            function = call["function"]
            arguments = json.loads(function["arguments"])
            if not isinstance(arguments, dict):
                raise ValueError("tool arguments must be an object")
            value = toolbox.call(function["name"], arguments)
        except (KeyError, TypeError, ValueError) as exc:
            value = {"error": str(exc)[:500]}
        responses.append({"role": "tool", "tool_call_id": call["id"],
                          "content": json.dumps(value, sort_keys=True, ensure_ascii=True)})
    return [assistant] + responses


def _parse_diagnosis(message, arm):
    if message.get("tool_calls"):
        raise ValueError("a final answer must contain Diagnosis JSON, not tool calls")
    content = message.get("content")
    if not isinstance(content, str):
        raise ValueError("final answer content must be a JSON string")
    diagnosis = Diagnosis.model_validate_json(content)
    # The flag identifies our fallback paths, never a model's own classification.
    for evidence in diagnosis.evidence:
        evidence.auto = False
    if arm == "llm_raw" and any(item.source == "frame" for item in diagnosis.evidence):
        raise ValueError("llm_raw must cite log lines; frame citations are not allowed")
    return diagnosis


def initial_messages(arm, view, raw_char_budget):
    instructions, hashes = prompts(arm)
    sources = ", ".join(view.allowed_sources)
    instructions += "\nObservation view: " + view.name + "; available logs: " + sources + "."
    messages = [{"role": "system", "content": instructions}]
    trimming = {}
    if arm == "llm_raw":
        text, trimming = raw_logs(view, raw_char_budget)
        messages.append({"role": "user", "content": "Diagnose these observations:\n" + text})
    else:
        messages.append({"role": "user", "content": "Diagnose the Wi-Fi connection attempt."})
    return messages, hashes, trimming


def preflight(arm, view, config, raw_char_budget=48000):
    """Plan the largest permitted request before contacting a model.

    Later tool output is bounded by the disclosed transcript budget. A tool result
    exceeding that budget is replaced with an explicit omission response and the
    model is asked to finish; every actual request is independently checked too.
    """
    messages, _, _ = initial_messages(arm, view, raw_char_budget)
    definitions = Toolbox(view).definitions if arm == "llm_tools" else None
    initial = check_context(config, messages, definitions)
    remaining = config.context_length - config.max_tokens - initial - REPAIR_RESERVE
    if remaining < 0:
        raise ContextLimitError(
            f"{config.name}: initial prompt estimate {initial} plus repair reserve "
            f"{REPAIR_RESERVE} and max_tokens {config.max_tokens} exceed declared "
            f"context_length {config.context_length}")
    history = min(TOOL_HISTORY_BUDGET, remaining) if arm == "llm_tools" else 0
    return {"estimator": "serialized_utf8_bytes_plus_framing",
            "initial_prompt_tokens_estimate": initial,
            "largest_prompt_tokens_estimate": initial + history + REPAIR_RESERVE,
            "tool_history_budget": history, "repair_reserve": REPAIR_RESERVE,
            "max_tokens": config.max_tokens, "context_length": config.context_length}


def run_arm(arm, view, *, client=None, trace=None, run_id="", bundle_id="",
            raw_char_budget=48000, max_tool_rounds=10):
    if not isinstance(view, View):
        raise TypeError("run_arm requires a redacted View, not a raw bundle")
    if arm == "rules":
        from triage.rules import diagnose
        started = time.monotonic()
        diagnosis = diagnose(view)
        for evidence in diagnosis.evidence:
            evidence.auto = True
        return ArmResult(diagnosis, latency_ms=(time.monotonic() - started) * 1000)
    if arm not in {"llm_raw", "llm_tools"}:
        raise ValueError("unknown comparison arm: " + arm)
    if client is None:
        raise ValueError("an LLM arm requires a configured client")
    if arm == "llm_tools" and not client.config.supports_tools:
        raise ValueError("the configured model does not support tools")
    if not 0 <= max_tool_rounds <= 10:
        raise ValueError("max_tool_rounds must be between zero and ten")

    started = time.monotonic()
    plan = preflight(arm, view, client.config, raw_char_budget)
    messages, hashes, trimming = initial_messages(arm, view, raw_char_budget)
    toolbox = Toolbox(view)
    result = ArmResult(unknown(view), trimming=trimming, prompt_hashes=hashes,
                       context_plan=plan)
    tool_rounds = 0
    repair_used = False
    call_index = 0
    while True:
        tools = None
        if arm == "llm_tools" and tool_rounds < max_tool_rounds and not repair_used:
            tools = toolbox.definitions
        estimated = estimate_prompt_tokens(messages, tools)
        if estimated > plan["largest_prompt_tokens_estimate"]:
            result.outcome = "CONTEXT_REJECTED"
            result.error = "Next request exceeds the preflight planned prompt limit"
            result.context_plan["rejected_prompt_tokens_estimate"] = estimated
            break
        try:
            completion = client.complete(messages, tools, run_id=run_id, bundle_id=bundle_id,
                                         arm=arm, call_index=call_index, prompt_hashes=hashes,
                                         view=view.name)
        except ContextLimitError as exc:
            result.outcome = "CONTEXT_REJECTED"
            result.error = str(exc)
            break
        call_index += 1
        result.finish_reason = completion.record["finish_reason"]
        result.truncation_suspected |= completion.record["truncation_suspected"]
        result.pricing = completion.record["pricing"]
        call_cost = completion.record["cost_inr"]
        if call_cost is None or result.cost_inr is None:
            result.cost_inr = None
        else:
            result.cost_inr += call_cost
        for kind in result.tokens:
            value = completion.record["tokens"][kind]
            if value is None or result.tokens[kind] is None:
                result.tokens[kind] = None
            else:
                result.tokens[kind] += value
        if result.finish_reason == "length":
            result.outcome = "TRUNCATED"
            completion.record["outcome"] = "TRUNCATED"
            completion.record["validation_stage"] = "truncated"
            if trace is not None:
                trace.append(completion.record)
            break
        if completion.error:
            result.outcome = "ERROR"
            result.error = completion.error
            if trace is not None:
                trace.append(completion.record)
            break
        message = completion.message
        try:
            if message.get("tool_calls") and tools:
                additions = _tool_results(message, toolbox)
                projected = estimate_prompt_tokens(messages + additions, toolbox.definitions)
                maximum = plan["initial_prompt_tokens_estimate"] + plan["tool_history_budget"]
                if projected > maximum:
                    omitted = sum(len(item["content"]) for item in additions[1:])
                    for response in additions[1:]:
                        response["content"] = json.dumps({
                            "error": "Tool output omitted because the context transcript budget is exhausted.",
                            "truncated": True})
                    result.trimming.setdefault("tool_context", []).append({
                        "call_index": call_index - 1, "omitted_chars": omitted,
                        "reason": "context transcript budget"})
                    tool_rounds = max_tool_rounds - 1
                messages.extend(additions)
                tool_rounds += 1
                completion.record["validation_passed"] = True
                completion.record["validation_stage"] = "tool_calls"
                if trace is not None:
                    trace.append(completion.record)
                if tool_rounds == max_tool_rounds:
                    messages.append({"role": "user", "content":
                                     "Tool budget exhausted. Return the final Diagnosis JSON now."})
                continue
            result.diagnosis = _parse_diagnosis(message, arm)
            completion.record["validation_passed"] = True
            completion.record["validation_stage"] = "diagnosis"
            if trace is not None:
                trace.append(completion.record)
            break
        except (ValueError, TypeError, ValidationError) as exc:
            if isinstance(exc, ValidationError):
                error = json.dumps(exc.errors(include_url=False, include_input=False))
            else:
                error = str(exc)
            completion.record["validation_error"] = error
            if trace is not None:
                trace.append(completion.record)
            if repair_used:
                result.schema_failure = True
                result.outcome = "SCHEMA_FAILURE"
                result.error = "diagnosis schema validation failed after one repair"
                break
            repair_used = True
            # The complete invalid response remains in the trace. The repair
            # request needs the validation error, not an unbounded invalid body.
            messages.append({"role": "user", "content":
                             "Validation failed: " + error[:1000] +
                             "\nReturn one corrected Diagnosis JSON object. No tools are available."})
    result.latency_ms = (time.monotonic() - started) * 1000
    return result
