"""Deterministic HTTP responses for offline client and tool-loop tests."""

import json

import httpx


def answer(root_cause="unknown", source="hostapd", ref=1, quote="wlan0: AP-ENABLED"):
    diagnosis = {"root_cause": root_cause,
                 "evidence": [{"source": source, "ref": ref, "quote": quote}],
                 "confidence": 0.25, "fix": "Collect more observations before changing configuration."}
    return {"role": "assistant", "content": json.dumps(diagnosis)}


def tool_call(name="capture_summary", arguments=None, call_id="call-1"):
    return {"role": "assistant", "content": None, "tool_calls": [
        {"id": call_id, "type": "function", "function": {
            "name": name, "arguments": json.dumps(arguments or {})}}]}


def envelope(message, model="fake-resolved-version"):
    finish = "tool_calls" if message.get("tool_calls") else "stop"
    return {"id": "fake-response", "model": model,
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 13, "completion_tokens": 7, "total_tokens": 20}}


class ScriptedModel:
    """Items are assistant messages, HTTP responses, or request exceptions."""

    def __init__(self, responses, repeat_last=False):
        if not responses:
            raise ValueError("a response script must not be empty")
        self.responses = list(responses)
        self.repeat_last = repeat_last
        self.requests = []
        self.transport = httpx.MockTransport(self.respond)

    def respond(self, request):
        self.requests.append(json.loads(request.content))
        index = len(self.requests) - 1
        if index >= len(self.responses):
            if not self.repeat_last:
                raise AssertionError("fake response script exhausted")
            index = len(self.responses) - 1
        response = self.responses[index]
        if isinstance(response, Exception):
            raise response
        if isinstance(response, httpx.Response):
            return response
        return httpx.Response(200, json=envelope(response))


def malformed():
    return {"role": "assistant", "content": "this is not JSON"}


def fabricated():
    return answer(source="frame", ref=999999, quote="invented observation")
