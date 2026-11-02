"""Qt-free background task manager (cancellable, with progress callbacks)."""
from __future__ import annotations

import logging
import threading
import traceback
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field

log = logging.getLogger("reforge.tasks")


class Cancelled(Exception):
    pass


@dataclass
class TaskContext:
    task_id: str
    cancel_event: threading.Event = field(default_factory=threading.Event)
    on_progress: Callable[[int, str], None] | None = None

    def check(self) -> None:
        if self.cancel_event.is_set():
            raise Cancelled()

    def progress(self, pct: int, msg: str = "") -> None:
        self.check()
        if self.on_progress:
            self.on_progress(max(0, min(100, pct)), msg)


class TaskManager:
    def __init__(self, workers: int = 2):
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="reforge")
        self._tasks: dict[str, tuple[TaskContext, Future]] = {}

    def submit(self, fn: Callable[[TaskContext], object], on_progress=None, on_done=None) -> str:
        ctx = TaskContext(uuid.uuid4().hex[:12], on_progress=on_progress)

        def wrapper():
            try:
                res = fn(ctx)
                status = "done"
            except Cancelled:
                res, status = None, "cancelled"
            except Exception as e:  # noqa: BLE001 - surfaced to UI
                log.error("task %s failed: %s\n%s", ctx.task_id, e, traceback.format_exc())
                res, status = e, "failed"
            if on_done:
                on_done(ctx.task_id, status, res)
            return res

        self._tasks[ctx.task_id] = (ctx, self._pool.submit(wrapper))
        return ctx.task_id

    def cancel(self, task_id: str) -> None:
        if task_id in self._tasks:
            self._tasks[task_id][0].cancel_event.set()

    def active(self) -> list[str]:
        return [t for t, (_, f) in self._tasks.items() if not f.done()]

    def shutdown(self) -> None:
        for ctx, _ in self._tasks.values():
            ctx.cancel_event.set()
        self._pool.shutdown(wait=False, cancel_futures=True)
