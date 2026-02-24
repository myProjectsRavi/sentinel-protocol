"""Sentinel Protocol Python adapters for LangChain, LlamaIndex, and CrewAI.

Zero external dependencies. Uses urllib from Python stdlib.
"""

from .callbacks import (
    CrewAISentinelHook,
    LangChainSentinelCallbackHandler,
    LlamaIndexSentinelCallback,
    SentinelScanError,
    scan_prompt,
)

__all__ = [
    "scan_prompt",
    "SentinelScanError",
    "LangChainSentinelCallbackHandler",
    "LlamaIndexSentinelCallback",
    "CrewAISentinelHook",
]
