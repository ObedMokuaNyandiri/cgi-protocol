"""
CGI Protocol — Server-Sent Events (SSE) Broadcaster
=====================================================
Provides a real-time event stream for the Live Compliance Dashboard.

Architecture:
  - `AttestationBroadcaster` is a singleton held in AppState.
  - `api_gateway.py` calls `broadcaster.publish(event)` after every
    successful attestation (zero latency overhead — just a queue.put_nowait).
  - The `/v1/stream/attestations` endpoint subscribes a new asyncio.Queue,
    streams events to the client via SSE, and unsubscribes on disconnect.

Design principles:
  - Zero polling: push-based via asyncio.Queue.
  - Zero overhead on the inference hot path: put_nowait is O(1).
  - Automatic cleanup: disconnected queues are removed on next publish cycle.
  - No external dependencies: pure asyncio + Python stdlib.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator

logger = logging.getLogger("cgi.sse")

# Maximum events buffered per subscriber queue before older events are dropped.
_QUEUE_MAX_SIZE = 200

# Keepalive comment interval in seconds (prevents proxy timeouts on idle streams).
_KEEPALIVE_INTERVAL = 25


class AttestationBroadcaster:
    """
    Fan-out broadcaster for real-time attestation events.

    Usage:
        # At startup (AppState):
        broadcaster = AttestationBroadcaster()

        # On every inference (hot path — O(1)):
        broadcaster.publish({"type": "ATTESTATION", ...})

        # In the SSE endpoint:
        async for chunk in broadcaster.subscribe():
            yield chunk
    """

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()
        self._event_count = 0

    def publish(self, event: dict[str, Any]) -> None:
        """
        Publish an event to all connected subscribers.
        Called from sync context (inference handler) — uses put_nowait.
        Dead queues (full) are silently dropped; they'll be cleaned up
        on the next subscribe/unsubscribe cycle.
        """
        event.setdefault("published_at", time.time())
        event.setdefault("seq", self._event_count)
        self._event_count += 1

        payload = json.dumps(event, separators=(",", ":"))
        sse_line = f"data: {payload}\n\n"

        dead: list[asyncio.Queue] = []
        for q in self._subscribers:
            try:
                q.put_nowait(sse_line)
            except asyncio.QueueFull:
                dead.append(q)

        # Lazily prune queues that are full (subscriber fell too far behind)
        for q in dead:
            try:
                self._subscribers.remove(q)
                logger.warning("SSE_SUBSCRIBER_DROPPED | queue full, removing slow subscriber")
            except ValueError:
                pass

    async def subscribe(self) -> AsyncGenerator[str, None]:
        """
        Async generator that yields SSE-formatted strings.
        Yields a keepalive comment every _KEEPALIVE_INTERVAL seconds
        to prevent proxy / browser timeouts on idle streams.

        Automatically unsubscribes when the client disconnects (generator is
        garbage collected or GeneratorExit is thrown).
        """
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=_QUEUE_MAX_SIZE)

        async with self._lock:
            self._subscribers.append(queue)
        logger.info("SSE_SUBSCRIBE | total_subscribers=%d", len(self._subscribers))

        # Immediately send a connection confirmation event
        yield (
            f"data: {json.dumps({'type': 'CONNECTED', 'timestamp': time.time(), 'message': 'CGI Protocol live attestation stream connected.'})}\n\n"
        )

        try:
            while True:
                try:
                    # Wait for an event, but timeout periodically to send keepalives
                    chunk = await asyncio.wait_for(queue.get(), timeout=_KEEPALIVE_INTERVAL)
                    yield chunk
                except asyncio.TimeoutError:
                    # Send SSE comment as keepalive (browsers / proxies use this)
                    yield f": keepalive {int(time.time())}\n\n"
        except (GeneratorExit, asyncio.CancelledError):
            pass
        finally:
            async with self._lock:
                try:
                    self._subscribers.remove(queue)
                except ValueError:
                    pass
            logger.info("SSE_UNSUBSCRIBE | total_subscribers=%d", len(self._subscribers))

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)
