import asyncio
import math
import time

if __name__ == "ratelimiter":
    from contextmanager import AsyncContextManager
else:
    from .contextmanager import AsyncContextManager

class RateLimiter(AsyncContextManager):
    # max_actions - number actions that can be taken in a given window of time
    # action_window - time in seconds that n actions can occur in
    def __init__(self, max_actions=10, action_window=1):
        super().__init__()
        self.max_actions_per_window = max_actions
        self.min_measured_actions_per_window = math.inf
        self.max_measured_actions_per_window = 0
        self.avg_measured_actions_per_window = 0
        self.action_count = 0
        self.reset_count = 0
        self.current_actions_per_window = 0
        self.action_window = action_window
        self.ratelimit_reset = None
        self.awaiting_reset = False

    async def __aenter__(self):
        if not self.ratelimit_reset:
            self.ratelimit_reset = asyncio.Event()
        return self

    async def __aexit__(self,exc_type, exc, tb):
        await super().__aexit__(exc_type, exc, tb, __name__)

    async def run(self, action):
        if action not in self.awaitable_list:
            self.awaitable_list.append(action)
        # Create a reset task if one hasn't already been created
        if not self.awaiting_reset:
            self.awaiting_reset = True
            reset_task = asyncio.create_task(self.reset_limit(self.action_count))
            self.awaitable_list.append(reset_task)
        # Run tasks till ratelimit is hit, then wait till window resets before running more tasks
        if not self.ratelimit_hit():
            self.current_actions_per_window += 1
            self.action_count += 1
            result = await action
            self.awaitable_list.remove(action)
            return result
        else:
            self.ratelimit_reset.clear()
            await self.ratelimit_reset.wait()
            return await self.run(action)

    def ratelimit_hit(self):
        return self.current_actions_per_window == self.max_actions_per_window

    def stats(self):
        return {
            "window_size":self.action_window,
            "max_actions_per_window":self.max_actions_per_window,
            "min_measured_actions_per_window":self.min_measured_actions_per_window,
            "max_measured_actions_per_window":self.max_measured_actions_per_window,
            "avg_measured_actions_per_window":self.avg_measured_actions_per_window,
            "action_count":self.action_count,
        }

    async def reset_limit(self, current_period_actions_start):
        await asyncio.sleep(self.action_window)
        current_period_actions_end = self.action_count
        current_actions_per_window = current_period_actions_end - current_period_actions_start
        self.max_measured_actions_per_window = max(self.max_measured_actions_per_window, current_actions_per_window)
        self.min_measured_actions_per_window = min(self.min_measured_actions_per_window, current_actions_per_window)
        self.avg_measured_actions_per_window = (self.reset_count * self.avg_measured_actions_per_window + \
            current_actions_per_window) / (self.reset_count + 1)
        self.reset_count += 1
        self.awaiting_reset = False
        self.current_actions_per_window = 0
        self.ratelimit_reset.set()
