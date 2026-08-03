import os
import random
import time


class FileLock:
    def __init__(self, lock_file, timeout=10):
        self.lock_file = lock_file
        self.timeout = timeout
        self.fd = None

    def __enter__(self):
        start_time = time.time()
        while True:
            try:
                # O_CREAT and O_EXCL ensures that the file is created atomically.
                # If it already exists, this raises FileExistsError (OSError).
                self.fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except OSError:
                if time.time() - start_time >= self.timeout:
                    raise TimeoutError(f"Could not acquire lock {self.lock_file} within {self.timeout}s")
                time.sleep(0.01 + random.random() * 0.05)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.fd is not None:
            os.close(self.fd)
        try:
            os.remove(self.lock_file)
        except OSError:
            pass
