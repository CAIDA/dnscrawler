import asyncio

class RateLimiter:
    # max_actions - number actions that can be taken in a given window of time
    # action_window - time in seconds that n actions can occur in
    def __init__(self, max_actions=10, action_window=1):
        self.max_actions_per_window = max_actions
        self.current_actions_per_window = 0
        self.action_window = action_window
        self.ratelimit_reset = None
        self.awaiting_reset = False
        self.awaitable_list = []

    async def __aenter__(self):
        if not self.ratelimit_reset:
            self.ratelimit_reset = asyncio.Event()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        # Wait for remaining awaitables to finish executing before closing
        exit_awaitables = []
        for aw in self.awaitable_list:
            if str(type(aw)) == "<class 'coroutine'>":
                # Coroutines cr_frame gets set to None after execution
                if aw.cr_frame:
                    exit_awaitables.append(aw)
            elif not aw.done():
                exit_awaitables.append(aw)
        await asyncio.gather(*exit_awaitables)

    async def run(self, action):
        if action not in self.awaitable_list:
            self.awaitable_list.append(action)
        # Create a reset task if one hasn't already been created
        if not self.awaiting_reset:
            self.awaiting_reset = True
            reset_task = asyncio.create_task(self.reset_limit())
            self.awaitable_list.append(reset_task)
        # Run tasks till ratelimit is hit, then wait till window resets before running more tasks
        if not self.ratelimit_hit():
            self.current_actions_per_window += 1
            result = await action
            self.awaitable_list.remove(action)
            return result
        else:
            await self.ratelimit_reset.wait()
            return await self.run(action)

    def ratelimit_hit(self):
        return self.current_actions_per_window == self.max_actions_per_window

    async def reset_limit(self):
        self.ratelimit_reset.clear()
        await asyncio.sleep(self.action_window)
        self.awaiting_reset = False
        self.current_actions_per_window = 0
        self.ratelimit_reset.set()
