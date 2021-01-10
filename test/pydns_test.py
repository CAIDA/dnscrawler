import sys
sys.path.append("../")
from dnscrawler import PyDNS
from dnscrawler.pydns import QueryResponse, DNSRecord
import asyncio
import json
import logging
import tracemalloc
from random import random

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
        print(await asyncio.create_task(pydns.query("google.com.", "192.33.14.30")))
        print(json.dumps(pydns.stats(), indent=4))
        
async def test_pydns_ratelimiting():
    async with PyDNS([],ipv4_only=True) as pydns:
        pydns.MAX_REQUESTS_PER_NAMESERVER_SECOND=3
        pydns.MAX_REQUESTS_PER_NAMESERVER_SECOND=3
        tasks = []
        tasks.append(pydns.query("google.com.", "192.5.6.30"))
        tasks.append(pydns.query("amazon.com.", "192.5.6.30"))
        tasks.append(pydns.query("netflix.com.", "192.5.6.30"))
        results = await asyncio.gather(*tasks)
        # print(json.dumps(results, indent=4))
        print(pydns.query_cache.cache)
    logger.info(json.dumps(pydns.stats(), indent=4))

def query_response_test():
    records = []
    for i in range(3):
        records.append(DNSRecord("name", random(), "rrclass", "rrtype", f"data{random()}"))
    rcodes = {'NS':0, 'A':0, 'AAAA':0}
    response = QueryResponse(records, rcodes)
    print(response)
    copy = response.copy()
    copy.data.append(DNSRecord("name", random(), "rrclass", "rrtype", f"data{random()}"))
    copy.rcodes['A'] = 1
    copy.nameserver = 'asd'
    print(copy)
    print(response)

def dns_record_test():
    r = DNSRecord("google.com", "500", "IN", "A", "ns1.google.com")
    print(r)
    a = set()
    a.add(r)
    r2 = r.copy()
    print(r2)
    print(r==r2)
    a.add(r2)
    print(a)
    r2.name="goa"
    print(r2)
    print(r)
    print(r==r2)
    a.add(r2)
    print(a)

if __name__ == "__main__":
    asyncio.run(test_pydns_caching())
    # asyncio.run(test_pydns_ratelimiting())
    # query_response_test()
    # dns_record_test()