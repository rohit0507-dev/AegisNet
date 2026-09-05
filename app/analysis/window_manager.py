import time


class WindowManager:

    def __init__(self, window_seconds=5):
        self.window_seconds = window_seconds
        self.start_time = time.time()

    def is_expired(self):
        return time.time() - self.start_time >= self.window_seconds

    def reset(self):
        self.start_time = time.time()

    def elapsed(self):
        return time.time() - self.start_time


if __name__ == "__main__":
    manager = WindowManager(5)

    print("======================================")
    print("       AEGISNET WINDOW MANAGER")
    print("======================================")
    print(f"Window Duration : {manager.window_seconds} seconds")
    print("Window manager initialized successfully.")