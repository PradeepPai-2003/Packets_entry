import collections
import threading
import time
from typing import Optional, Generic, TypeVar

T = TypeVar('T')

class ThreadSafeQueue(Generic[T]):
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.queue = collections.deque()
        self.lock = threading.Lock()
        self.not_empty = threading.Condition(self.lock)
        self.not_full = threading.Condition(self.lock)
        self._shutdown = False

    def push(self, item: T) -> None:
        """Push an item onto the queue, blocking if the queue is full."""
        with self.lock:
            while len(self.queue) >= self.max_size and not self._shutdown:
                self.not_full.wait()
            if self._shutdown:
                return
            self.queue.append(item)
            self.not_empty.notify()

    def try_push(self, item: T) -> bool:
        """Try to push an item onto the queue without blocking. Returns True if successful."""
        with self.lock:
            if len(self.queue) >= self.max_size or self._shutdown:
                return False
            self.queue.append(item)
            self.not_empty.notify()
            return True

    def pop(self) -> Optional[T]:
        """Pop an item from the queue, blocking if the queue is empty. Returns None on shutdown."""
        with self.lock:
            while not self.queue and not self._shutdown:
                self.not_empty.wait()
            if not self.queue:
                return None
            item = self.queue.popleft()
            self.not_full.notify()
            return item

    def pop_with_timeout(self, timeout_seconds: float) -> Optional[T]:
        """Pop an item from the queue, blocking for at most timeout_seconds. Returns None on timeout or shutdown."""
        with self.lock:
            start = time.time()
            while not self.queue and not self._shutdown:
                elapsed = time.time() - start
                remaining = timeout_seconds - elapsed
                if remaining <= 0:
                    return None
                self.not_empty.wait(remaining)
            if not self.queue:
                return None
            item = self.queue.popleft()
            self.not_full.notify()
            return item

    def empty(self) -> bool:
        """Return True if the queue is empty."""
        with self.lock:
            return len(self.queue) == 0

    def size(self) -> int:
        """Return the number of items currently in the queue."""
        with self.lock:
            return len(self.queue)

    def shutdown(self) -> None:
        """Wake up all waiting threads and mark the queue as shut down."""
        with self.lock:
            self._shutdown = True
            self.not_empty.notify_all()
            self.not_full.notify_all()

    def is_shutdown(self) -> bool:
        """Return True if the queue has been shut down."""
        with self.lock:
            return self._shutdown
