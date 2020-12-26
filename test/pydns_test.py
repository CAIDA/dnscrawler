import sys
sys.path.append("../")
from dnscrawler import PyDNS
import asyncio
import json
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s:%(message)s')

async def main():
    pydns = PyDNS([],ipv4_only=True)
    tasks = []
    tasks.append(pydns.query("google.com.", "192.5.6.30"))
    tasks.append(pydns.query("google.com.", "192.5.6.30"))
    results = await asyncio.gather(*tasks)
    print(json.dumps(results, indent=4))
    print(await asyncio.create_task(pydns.query("google.com.", "192.5.6.30")))

if __name__ == "__main__":
    asyncio.run(main())