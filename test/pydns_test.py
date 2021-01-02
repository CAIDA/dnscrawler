import sys
sys.path.append("../")
from dnscrawler import PyDNS
import asyncio
import json
import logging
import tracemalloc

tracemalloc.start()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s:%(message)s')
logger = logging.getLogger(__name__)
async def test_pydns_caching():
    async with PyDNS([],ipv4_only=True) as pydns:
        tasks = []
        tasks.append(pydns.query("google.com.", "192.5.6.30"))
        tasks.append(pydns.query("google.com.", "192.5.6.30"))
        results = await asyncio.gather(*tasks)
        # print(json.dumps(results, indent=4))
        print(await asyncio.create_task(pydns.query("google.com.", "192.5.6.30")))
        print(await asyncio.create_task(pydns.query("google.com.", "192.5.6.30")))
        print(json.dumps(pydns.stats(), indent=4))
        
async def test_pydns_ratelimiting():
    async with PyDNS([],ipv4_only=True,MAX_REQUESTS_PER_NAMESERVER_SECOND=10) as pydns:
        tasks = []
        tasks.append(pydns.query("google.com.", "192.5.6.30"))
        tasks.append(pydns.query("amazon.com.", "192.5.6.30"))
        tasks.append(pydns.query("netflix.com.", "192.5.6.30"))
        results = await asyncio.gather(*tasks)
        print(json.dumps(results, indent=4))
    logger.info(json.dumps(pydns.stats(), indent=4))

if __name__ == "__main__":
    # asyncio.run(test_pydns_caching())
    asyncio.run(test_pydns_ratelimiting())