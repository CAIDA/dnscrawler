import sys
sys.path.append("../")
import logging
import json
import time

import asyncio

from dnscrawler import DNSResolver, load_schema, SOCKSProxy
from dnscrawler.logger import log

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s:%(message)s')

logger = logging.getLogger(__name__)
async def main():
    start_time = float(time.time())
    # proxy = SOCKSProxy("192.172.226.186", "1080")
    # async with DNSResolver(socket_factories=[proxy],ipv4_only=True) as resolver:
    async with DNSResolver(ipv4_only=True) as resolver:
        # resolver = DNSResolver()
        host_dependencies = await resolver.get_host_dependencies("google.com")
        # Empty non-terminal
        # host_dependencies = await resolver.get_host_dependencies("caag.state.ca.us")
        # Hazardous domain
        # host_dependencies = await resolver.get_host_dependencies("PREGNANCYCALCULATE.COM.")
        # Cross zone loops
        # host_dependencies = await resolver.get_host_dependencies("amazon.com")
        # Early ns records
        # host_dependencies = await resolver.get_host_dependencies("aridns.net.au")
        # Retry domain records due to timeout
        # host_dependencies = await resolver.get_host_dependencies("AMERICUSGA.GOV")
        # Has NS record with '.' for record data
        # host_dependencies = await resolver.get_host_dependencies("nowdns.net")
        # Root as hostname
        # host_dependencies = await resolver.get_host_dependencies(".")
        finish_time = float(time.time())
        duration = finish_time - start_time
        print(json.dumps(host_dependencies))
        print(f"Duration:{duration}")
    # logger.info(json.dumps(resolver.pydns.stats(), indent=4))

if __name__ == "__main__":
    asyncio.run(main())   

