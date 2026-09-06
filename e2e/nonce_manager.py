"""Per-session nonce manager for the technocore-e2e-crypto protocol.

A nonce manager is the bridge between the streaming AEAD record layer and
the higher-level message API. Each session has two directions (A->B and
B->A); in each direction every protected record carries a strictly
monotonically increasing 64-bit counter. The counter is mixed into the
HKDF info string so a successful AEAD decrypt implies the counter was
the expected next value for that direction.

The manager is intentionally minimal:
  * thread-safe (one lock per direction),
  * bounded (refuses to advance past 2^63 - 1 to keep room for rekey),
  * replay-aware (rejects out-of-order or duplicate counters).

It stores nothing on disk; persistence is the caller's job. A companion
class `RekeyingNonceManager` shows how to swap in a fresh session once
the counter window is exhausted.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional


class NonceError(Exception):
    """Raised on any nonce / counter policy violation."""


@dataclass
class DirectionState:
    """State for one (sender -> receiver) direction of a session."""

    next_send: int = 0           # counter for the next outgoing record
    highest_recv: int = -1       # highest counter accepted so far
    # Optional bit-window replay cache. For our 64-bit counters we keep
    # the last 1024 counters as a compact set; older replays are rejected
    # because they fall behind `highest_recv - 1023`.
    replay_window: set[int] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)

    REPLAY_WINDOW_SIZE = 1024
    COUNTER_MAX = (1 << 63) - 1  # stop short of 2^63 for rekey headroom

    def alloc_send(self) -> int:
        with self.lock:
            if self.next_send > self.COUNTER_MAX:
                raise NonceError(
                    f"send counter exhausted ({self.next_send}); rekey required"
                )
            n = self.next_send
            self.next_send += 1
            return n

    def accept_recv(self, counter: int) -> int:
        """Validate an incoming counter. Returns the counter on success,
        raises NonceError on replay / out-of-order / overflow."""
        with self.lock:
            if counter < 0 or counter > self.COUNTER_MAX:
                raise NonceError(f"counter out of range: {counter}")
            if counter <= self.highest_recv:
                # Must be inside the replay window to be considered a replay
                # (rather than simply too old). Otherwise treat as poison.
                if counter < self.highest_recv - self.REPLAY_WINDOW_SIZE + 1:
                    raise NonceError(f"counter too old: {counter}")
                if counter in self.replay_window:
                    raise NonceError(f"replayed counter: {counter}")
                raise NonceError(f"out-of-order counter: {counter}")
            # New high water mark: slide the window forward.
            self.replay_window.add(counter)
            if len(self.replay_window) > self.REPLAY_WINDOW_SIZE:
                # Drop the oldest entries (smallest counters).
                victim = min(self.replay_window)
                self.replay_window.discard(victim)
            self.highest_recv = counter
            return counter


@dataclass
class NonceManager:
    """Two-direction nonce state for a single session.

    `side` is just a label ("A" or "B") for diagnostics; the protocol
    is symmetric.
    """

    side: str
    outbound: DirectionState = field(default_factory=DirectionState)
    inbound: DirectionState = field(default_factory=DirectionState)
    session_id: Optional[bytes] = None  # 8 random bytes, set at init

    def alloc_send(self) -> int:
        return self.outbound.alloc_send()

    def accept_recv(self, counter: int) -> int:
        return self.inbound.accept_recv(counter)

    def counters_exhausted(self) -> bool:
        """True once either direction has hit its rekey threshold."""
        return (
            self.outbound.next_send > DirectionState.COUNTER_MAX
            or self.inbound.highest_recv > DirectionState.COUNTER_MAX
        )


@dataclass
class RekeyingNonceManager:
    """Wraps a NonceManager and rotates it when the counter window fills.

    Callers are expected to derive a new session (new HKDF salt + root key)
    and pass the freshly minted NonceManager into `replace()`. Outbound
    counters continue from 0 against the new session; the peer's inbound
    window is reset in lockstep because it learned the new session_id
    from the rekey handshake.
    """

    inner: NonceManager
    rekey_threshold: int = (1 << 50)  # ~1 quadrillion records; far in practice

    def alloc_send(self) -> int:
        if self.inner.outbound.next_send >= self.rekey_threshold:
            raise NonceError("rekey_threshold reached; caller must rekey")
        return self.inner.alloc_send()

    def accept_recv(self, counter: int) -> int:
        return self.inner.accept_recv(counter)

    def replace(self, fresh: NonceManager) -> None:
        self.inner = fresh


__all__ = [
    "NonceError",
    "DirectionState",
    "NonceManager",
    "RekeyingNonceManager",
]

<!-- Authored by Technocore agent DID did:key:z6MkwUFX8bCp4RZUyG3fod2wEVvRci7AY2h19fJWELAsomiC -->
