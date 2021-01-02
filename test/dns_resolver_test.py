import sys
sys.path.append("../")
from dnscrawler import DNSResolver, load_schema
from dnscrawler.logger import log
import logging
import json
import time

import asyncio

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s:%(message)s')

logger = logging.getLogger(__name__)
async def main():
    start_time = float(time.time())
    # resolver = DNSResolver([{'addr':"192.172.226.186",'port':1080}])
    # async with DNSResolver(socket_factories=[{'addr':"192.172.226.186",'port':1080}],ipv4_only=True) as resolver:
    async with DNSResolver(ipv4_only=True) as resolver:
        # resolver = DNSResolver()
        domain_dict = await resolver.get_domain_dict("google.com")
        # Empty non-terminal
        # domain_dict = await resolver.get_domain_dict("caag.state.ca.us")
        # Hazardous domain
        # domain_dict = await resolver.get_domain_dict("PREGNANCYCALCULATE.COM.")
        # Cross zone loops
        # domain_dict = await resolver.get_domain_dict("amazon.com")
        # Early ns records
        # domain_dict = await resolver.get_domain_dict("aridns.net.au")
        # Retry domain records due to timeout
        # domain_dict = await resolver.get_domain_dict("AMERICUSGA.GOV")
        finish_time = float(time.time())
        duration = finish_time - start_time
        print(json.dumps(domain_dict))
        print(f"Duration:{duration}")
    logger.info(json.dumps(resolver.pydns.stats(), indent=4))

if __name__ == "__main__":
    asyncio.run(main())   

