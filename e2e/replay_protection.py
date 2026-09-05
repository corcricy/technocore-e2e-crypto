"""
Replay protection for the technocore-e2e-crypto protocol.

Provides a thread-safe, bounded sliding-window replay cache that tracks recently
seen nonces / message counters and rejects duplicates. The cache is keyed by a
session identifier combined with a monotonically increasing per-direction
counter or a 96-bit AES-GCM nonce.

Design goals:

* Constant-time lookups are not required (the data being checked is not a
  secret), but the API surface is simple and forgiving.
* Memory is bounded via an LRU eviction policy so long-running sessions do not
  grow without limit.
* Concurrent use is safe on CPython thanks to the GIL, but we still take a
  re-entrant lock to keep semantics explicit and portable.
* The module is dependency-free beyond the standard library.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Tuple


class ReplayError(Exception):
    """Raised when a message is rejected as a replay."""


@dataclass
class ReplayProtectionConfig:
    """Configuration for :class:`ReplayProtectionWindow`.

    Attributes
    ----------
    max_counter_gap:
        Maximum acceptable forward gap when receiving out-of-order counters.
        Larger gaps cost memory; smaller gaps tighten security.
    max_nonce_window:
        Maximum number of recently seen 96-bit nonces to remember.
    clock_skew_seconds:
        Tolerance for clock-based freshness checks. Set to ``0`` to disable.
    """

    max_counter_gap: int = 1024
    max_nonce_window: int = 4096
    clock_skew_seconds: float = 30.0


@dataclass
class _SessionState:
    """Per-session bookkeeping."""

    rx_counter: int = 0  # highest counter accepted so far (receive direction)
    tx_counter: int = 0  # next counter to use for outbound messages
    nonce_window: Deque[Tuple[float, bytes]] = field(default_factory=deque)
    counter_window: "OrderedDict[int, None]" = field(default_factory=OrderedDict)


class ReplayProtectionWindow:
    """Bounded sliding window that rejects replayed messages.

    Two complementary checks are supported:

    1. **Counter check** — each direction carries an incrementing 64-bit counter
       (see :class:`e2e.session.EncryptedSession`). The receiver rejects any
       counter that is not strictly greater than the largest accepted counter
       minus ``max_counter_gap``, and rejects duplicates within the window.
    2. **Nonce check** — when AES-GCM is used directly with random nonces, the
       receiver records the last ``max_nonce_window`` nonces and rejects any
       duplicate.

    Either check can be used standalone; both can be combined for defence in
    depth.
    """

    def __init__(self, config: Optional[ReplayProtectionConfig] = None) -> None:
        self._config = config or ReplayProtectionConfig()
        self._sessions: Dict[bytes, _SessionState] = {}
        self._lock = threading.RLock()

    # ---- session lifecycle ------------------------------------------------

    def register_session(self, session_id: bytes) -> None:
        """Begin tracking ``session_id``.

        Calling this multiple times for the same id is safe; the prior state
        is cleared to avoid cross-session contamination after a re-handshake.
        """
        with self._lock:
            self._sessions[session_id] = _SessionState()

    def forget_session(self, session_id: bytes) -> None:
        """Drop all bookkeeping for ``session_id``."""
        with self._lock:
            self._sessions.pop(session_id, None)

    # ---- counter API ------------------------------------------------------

    def next_tx_counter(self, session_id: bytes) -> int:
        """Reserve and return the next outbound counter for ``session_id``."""
        with self._lock:
            state = self._require(session_id)
            value = state.tx_counter
            state.tx_counter += 1
            return value

    def check_rx_counter(self, session_id: bytes, counter: int) -> None:
        """Validate an inbound counter, raising :class:`ReplayError` on replay.

        On success the internal window is updated so future duplicates are
        rejected.
        """
        if counter < 0:
            raise ReplayError("negative counter")
        with self._lock:
            state = self._require(session_id)
            # Duplicate in window?
            if counter in state.counter_window:
                raise ReplayError(f"duplicate counter {counter}")
            # Too old?
            if counter + self._config.max_counter_gap <= state.rx_counter:
                raise ReplayError(
                    f"counter {counter} too old (rx={state.rx_counter})"
                )
            # Accept: slide the window forward.
            state.counter_window[counter] = None
            while (
                state.counter_window
                and state.rx_counter
                and next(iter(state.counter_window)) + self._config.max_counter_gap
                <= state.rx_counter
            ):
                state.counter_window.popitem(last=False)
            if counter > state.rx_counter:
                state.rx_counter = counter

    # ---- nonce API --------------------------------------------------------

    def check_nonce(
        self, session_id: bytes, nonce: bytes, received_at: Optional[float] = None
    ) -> None:
        """Validate a 12-byte AES-GCM nonce.

        ``received_at`` defaults to ``time.time()``; supply an explicit value
        in tests for determinism.
        """
        if len(nonce) != 12:
            raise ValueError("AES-GCM nonce must be 12 bytes")
        now = received_at if received_at is not None else time.time()
        with self._lock:
            state = self._require(session_id)
            cutoff = now - self._config.clock_skew_seconds
            # Drop stale entries.
            window = state.nonce_window
            while window and window[0][0] < cutoff:
                window.popleft()
            for _, seen in window:
                if seen == nonce:
                    raise ReplayError(f"duplicate nonce {nonce.hex()}")
            window.append((now, bytes(nonce)))
            while len(window) > self._config.max_nonce_window:
                window.popleft()

    # ---- introspection ---------------------------------------------------

    def stats(self, session_id: bytes) -> Dict[str, int]:
        """Return diagnostic counters for tests and metrics endpoints."""
        with self._lock:
            state = self._require(session_id)
            return {
                "rx_counter": state.rx_counter,
                "tx_counter": state.tx_counter,
                "counter_window_size": len(state.counter_window),
                "nonce_window_size": len(state.nonce_window),
            }

    # ---- internals -------------------------------------------------------

    def _require(self, session_id: bytes) -> _SessionState:
        try:
            return self._sessions[session_id]
        except KeyError as exc:
            raise ReplayError(f"unknown session {session_id.hex()}") from exc


__all__ = ["ReplayError", "ReplayProtectionConfig", "ReplayProtectionWindow"]

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
