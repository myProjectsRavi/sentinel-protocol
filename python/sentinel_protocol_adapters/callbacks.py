"""Framework adapters for local Sentinel prompt scanning.

All calls are local HTTP POST to /_sentinel/playground/analyze unless overridden.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

DEFAULT_PLAYGROUND_ENDPOINT = "http://127.0.0.1:8787/_sentinel/playground/analyze"


class SentinelScanError(RuntimeError):
    """Raised when local Sentinel scan request fails."""


EventSink = Callable[[Dict[str, Any]], None]


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=True)
    except Exception:
        return str(value)


def scan_prompt(
    prompt: str,
    endpoint: str = DEFAULT_PLAYGROUND_ENDPOINT,
    timeout_seconds: float = 3.0,
    correlation_id: str = "",
) -> Dict[str, Any]:
    """Run local Sentinel playground analysis for a prompt string."""

    body = {
        "prompt": _safe_str(prompt),
    }
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "content-type": "application/json",
            **({"x-sentinel-correlation-id": correlation_id} if correlation_id else {}),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            text = response.read().decode("utf-8")
            return json.loads(text) if text else {}
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        raise SentinelScanError(f"sentinel_scan_http_error:{error.code}:{raw}") from error
    except urllib.error.URLError as error:
        raise SentinelScanError(f"sentinel_scan_unreachable:{error.reason}") from error


class _BaseAdapter:
    def __init__(
        self,
        endpoint: str = DEFAULT_PLAYGROUND_ENDPOINT,
        timeout_seconds: float = 3.0,
        on_event: Optional[EventSink] = None,
        fail_open: bool = True,
    ) -> None:
        self.endpoint = endpoint
        self.timeout_seconds = float(timeout_seconds)
        self.on_event = on_event
        self.fail_open = bool(fail_open)

    def _emit(self, event: Dict[str, Any]) -> None:
        if self.on_event is not None:
            self.on_event(event)

    def _scan(self, prompt: str, correlation_id: str = "") -> Dict[str, Any]:
        return scan_prompt(
            prompt=prompt,
            endpoint=self.endpoint,
            timeout_seconds=self.timeout_seconds,
            correlation_id=correlation_id,
        )

    def _scan_safe(self, prompt: str, correlation_id: str = "") -> Dict[str, Any]:
        try:
            return self._scan(prompt, correlation_id=correlation_id)
        except SentinelScanError:
            if self.fail_open:
                return {
                    "summary": {
                        "risk": "unknown",
                        "engines_evaluated": 0,
                        "detections": 0,
                        "block_eligible": 0,
                    },
                    "error": "scan_failed_fail_open",
                }
            raise


class LangChainSentinelCallbackHandler(_BaseAdapter):
    """LangChain-style callback handler.

    Compatible with handler hooks like:
    - handleLLMStart(llm, prompts, runId)
    - handleLLMEnd(output, runId)
    - handleLLMError(error, runId)
    """

    def handleLLMStart(self, llm: Any, prompts: Optional[List[str]] = None, runId: Optional[str] = None) -> None:
        payload = {
            "framework": "langchain",
            "event": "agent.start",
            "run_id": _safe_str(runId),
            "model": _safe_str(getattr(llm, "modelName", None) or getattr(llm, "model", None)),
            "prompt_count": len(prompts or []),
        }
        if prompts:
            payload["scan"] = self._scan_safe("\n".join(_safe_str(item) for item in prompts), correlation_id=_safe_str(runId))
        self._emit(payload)

    def handleLLMEnd(self, output: Any, runId: Optional[str] = None) -> None:
        payload = {
            "framework": "langchain",
            "event": "agent.complete",
            "run_id": _safe_str(runId),
            "output_preview": _safe_str(output)[:512],
        }
        self._emit(payload)

    def handleLLMError(self, error: Exception, runId: Optional[str] = None) -> None:
        payload = {
            "framework": "langchain",
            "event": "agent.error",
            "run_id": _safe_str(runId),
            "error": _safe_str(error),
        }
        self._emit(payload)


class LlamaIndexSentinelCallback(_BaseAdapter):
    """LlamaIndex-style callback hook."""

    def on_start(self, meta: Optional[Dict[str, Any]] = None) -> None:
        meta = meta or {}
        prompt = _safe_str(meta.get("prompt", ""))
        payload = {
            "framework": "llamaindex",
            "event": "agent.start",
            "run_id": _safe_str(meta.get("runId", "")),
        }
        if prompt:
            payload["scan"] = self._scan_safe(prompt, correlation_id=payload["run_id"])
        self._emit(payload)

    def on_complete(self, meta: Optional[Dict[str, Any]] = None) -> None:
        meta = meta or {}
        self._emit(
            {
                "framework": "llamaindex",
                "event": "agent.complete",
                "run_id": _safe_str(meta.get("runId", "")),
            }
        )

    def on_error(self, error: Exception, meta: Optional[Dict[str, Any]] = None) -> None:
        meta = meta or {}
        self._emit(
            {
                "framework": "llamaindex",
                "event": "agent.error",
                "run_id": _safe_str(meta.get("runId", "")),
                "error": _safe_str(error),
            }
        )


class CrewAISentinelHook(_BaseAdapter):
    """CrewAI-style lifecycle hook adapter.

    Use from task/agent orchestration points and feed prompt/task context.
    """

    def on_task_start(self, task_description: str, run_id: str = "") -> None:
        scan = self._scan_safe(task_description, correlation_id=run_id)
        self._emit(
            {
                "framework": "crewai",
                "event": "task.start",
                "run_id": _safe_str(run_id),
                "scan": scan,
            }
        )

    def on_task_end(self, result: Any, run_id: str = "") -> None:
        self._emit(
            {
                "framework": "crewai",
                "event": "task.complete",
                "run_id": _safe_str(run_id),
                "result_preview": _safe_str(result)[:512],
            }
        )

    def on_task_error(self, error: Exception, run_id: str = "") -> None:
        self._emit(
            {
                "framework": "crewai",
                "event": "task.error",
                "run_id": _safe_str(run_id),
                "error": _safe_str(error),
            }
        )


class AutoGenSentinelHook(_BaseAdapter):
    """AutoGen-style lifecycle hook adapter."""

    def on_turn_start(self, message: Any, run_id: str = "") -> None:
        scan = self._scan_safe(_safe_str(message), correlation_id=run_id)
        self._emit(
            {
                "framework": "autogen",
                "event": "turn.start",
                "run_id": _safe_str(run_id),
                "scan": scan,
            }
        )

    def on_turn_complete(self, result: Any, run_id: str = "") -> None:
        self._emit(
            {
                "framework": "autogen",
                "event": "turn.complete",
                "run_id": _safe_str(run_id),
                "result_preview": _safe_str(result)[:512],
            }
        )

    def on_turn_error(self, error: Exception, run_id: str = "") -> None:
        self._emit(
            {
                "framework": "autogen",
                "event": "turn.error",
                "run_id": _safe_str(run_id),
                "error": _safe_str(error),
            }
        )


class LangGraphSentinelHook(_BaseAdapter):
    """LangGraph-style lifecycle hook adapter."""

    def on_node_start(self, node: Any, run_id: str = "") -> None:
        scan = self._scan_safe(_safe_str(node), correlation_id=run_id)
        self._emit(
            {
                "framework": "langgraph",
                "event": "node.start",
                "run_id": _safe_str(run_id),
                "scan": scan,
            }
        )

    def on_node_complete(self, result: Any, run_id: str = "") -> None:
        self._emit(
            {
                "framework": "langgraph",
                "event": "node.complete",
                "run_id": _safe_str(run_id),
                "result_preview": _safe_str(result)[:512],
            }
        )

    def on_node_error(self, error: Exception, run_id: str = "") -> None:
        self._emit(
            {
                "framework": "langgraph",
                "event": "node.error",
                "run_id": _safe_str(run_id),
                "error": _safe_str(error),
            }
        )
