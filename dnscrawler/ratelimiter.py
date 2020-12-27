import asyncio

class RateLimiter:
    # max_actions - number actions that can be taken in a given window of time
    # action_window - time in seconds that n actions can occur in
    def __init__(self, max_actions=10, action_window=1):
        self.max_actions_per_window = max_actions
        self.current_actions_per_window = 0
        self.action_window = action_window
        self.ratelimit_reset = asyncio.Event()
        self.awaiting_reset = False

    async def run(self, coro):
        if not self.awaiting_reset:
            self.reset_limit()
        if not self.ratelimit_hit():
            self.current_actions_per_window += 1
            return await coro
        else:
            await self.ratelimit_reset.wait()
            return await self.run(coro)

    async def ratelimit_hit(self):
        return self.current_actions_per_window == self.max_actions_per_window

    async def reset_limit(self):
        self.awaiting_reset = True
        self.ratelimit_reset.clear()
        await asyncio.sleep(self.action_window)
        self.awaiting_reset = False
        self.current_actions_per_window = 0
        self.ratelimit_reset.set()