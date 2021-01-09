import logging
import sys

import asyncio

logger = logging.getLogger(__name__)


class AsyncContextManager:
    '''AsyncContextManager is a base class for classes which rely on generating
    background asynchronous tasks and need to ensure execution before the
    program closes

    Attributes:
        awaitable_list (list): List of awaitables which will be waited on
            before the context manager closes
    '''

    def __init__(self):
        self.awaitable_list = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        # Wait for remaining awaitables to finish executing before closing
        exit_awaitables = []
        coros = []
        for aw in self.awaitable_list:
            if asyncio.iscoroutine(aw):
                # Coroutines cr_frame gets set to None after execution
                if aw.cr_frame:
                    exit_awaitables.append(aw)
                    coros.append(aw)
            elif asyncio.isfuture(aw):
                if not aw.done():
                    exit_awaitables.append(aw)
            else:
                raise TypeError("Non-awaitable found in awaitable list:", aw)
        for aw in exit_awaitables:
            try:
                await aw
            except Exception as exc:
                aw_str = str(aw)
                logger.exception(f"Error handling awaitable: {aw_str}")
