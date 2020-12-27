from dns import asyncquery as dnsquery, message as dnsmessage, rdatatype
from random import choice, random
from ipaddress import ip_address
from collections import defaultdict
import socket
import socks
import asyncio
import sys
import time
import math
import logging 

if __name__ == "pydns":
    import constants
    from asynciobackend import Backend
    from lru_cache import LRUCache
else:
    from . import constants
    from .asynciobackend import Backend
    from .lru_cache import LRUCache


logger = logging.getLogger(__name__)

class PyDNS:
    def __init__(self, socket_factories, ipv4_only=False):
        self.socket_factories = [socket.socket] + [self.create_socket_factory(factory['addr'], factory['port']) for factory in socket_factories];
        self.only_default_factory = len(self.socket_factories) == 1
        self.ipv4_only = ipv4_only
        # Time last request was sent
        self.last_send_time = None
        # Time first request was sent
        self.first_send_time = None
        # Total number of queries sent
        self.queries_sent = 0
        # Min, max, and avg queries per second
        self.min_queries_per_second = math.inf
        self.max_queries_per_second = 0
        self.avg_queries_per_second = 0
        self.awaiting_qps_calc = False
        # Set of nameservers to auto timeout all queries to
        self.timeout_nameservers = set()
        self.active_requests = defaultdict(list)
        self.active_queries = {}
        self.concurrent_request_limiter = asyncio.Semaphore(constants.MAX_CONCURRENT_REQUESTS)
        self.query_cache = LRUCache(constants.MAX_CACHED_QUERIES)

    def create_socket_factory(self, addr, port):
        def socket_factory(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0,fileno=None):
            s = socks.socksocket(family, type, proto, fileno)
            s.set_proxy(proxy_type=socks.SOCKS5, addr=addr, port=port)
            return s
        return socket_factory

    def get_socket_factory(self):
        if self.only_default_factory:
            return self.socket_factories[0]
        else:
            return choice(list(self.socket_factories))

    async def calculate_qps():
        self.awaiting_qps_calc = True
        current_period_starting_queries = self.queries_sent
        await asyncio.sleep(1)
        current_period_ending_queries = self.queries_sent
        current_queries_per_second = current_period_ending_queries - current_period_starting_queries
        self.max_queries_per_second = max(self.max_queries_per_second, queries_per_second)
        self.min_queries_per_second = min(self.min_queries_per_second, queries_per_second)
        self.avg_queries_per_second = self.queries_sent / (self.last_send_time - self.first_send_time)
        self.awaiting_qps_calc = False

    async def send_request(self, request, nameserver, retries=0):
        block_nameserver = False
        response = {"rcode":"timeout", "records":[]}
        # Multiply timeout duration by n each iteation (ie. if multiplier is 5, timeouts of 2s, 10s, 50s), 
        request_timeout = min(constants.REQUEST_TIMEOUT * (constants.TIMEOUT_MULTIPLIER ** retries), constants.MAX_TIMEOUT)
        # Return timeout for all nameservers that have previously timed out
        if nameserver not in self.timeout_nameservers:
            logger.debug(f"Starting request to {nameserver}")
            # Restrict number of concurrent requests to prevent
            # packet loss and avoid rate limiting
            if self.concurrent_request_limiter.locked():
                logger.debug("Waiting to send request: concurrent request limit hit")
            await self.concurrent_request_limiter.acquire()
            current_time = time.time()
            # Set last query sent time
            self.last_send_time = current_time
            # Set first query sent time if not set
            if not self.first_send_time:
                self.first_send_time = current_time
            self.queries_sent +=1
            # Flag to detect if query succeeded
            query_success = False
            try:
                query_task = asyncio.create_task(dnsquery.udp(q=request, where=nameserver, backend=Backend()))
                # Add request future to active_requests
                self.active_requests[nameserver].append(query_task)
                response_data = await asyncio.wait_for(query_task, timeout=request_timeout)
                query_success = True
                # Remove request future from active_requests
                self.active_requests[nameserver].remove(query_task)
                rcode = response_data.rcode()
                records = response_data.answer + response_data.additional + response_data.authority
                response = {"rcode":rcode, "records":records}
            except ConnectionRefusedError as err:
                logger.warning(f"Skipping future requests to {nameserver} due to ConnectionRefusedError")
                block_nameserver = True
            except ConnectionResetError as err:
                logger.warning(f"Skipping future requests to {nameserver} due to ConnectionResetError")
                block_nameserver = True
            except:
                # Query Timeout
                if retries > constants.REQUEST_RETRIES:
                    logger.warning(f"Skipping future requests to {nameserver} due to repeated timeout")
                    block_nameserver = True
            finally:
                self.concurrent_request_limiter.release()
                if block_nameserver:
                    self.timeout_nameservers.add(nameserver)
                    # Cancel all active futures for the blocked nameserver
                    for future in self.active_requests[nameserver]:
                        if not future.done():
                            future.cancel()
                        self.active_requests[nameserver].remove(future)
                elif not query_success:
                    response = await self.send_request(request, nameserver, retries+1)
        else:
            logger.debug(f"Request to {nameserver} skipped due to prior timeout")
        return response

    async def dns_response(self, domain,nameserver,retries=0):
        # print(f"querying {domain} at {nameserver}")
        record_types = (rdatatype.NS, rdatatype.A, rdatatype.AAAA)
        records = []
        rcodes = {}
        # If ipv4_only flag set, return timeout for all ipv6 queries
        # Return timeout for all nameservers that have previously timed out
        if (not self.ipv4_only or ip_address(nameserver).version == 4) and nameserver not in self.timeout_nameservers:
            # dnsquery.socket_factory = self.get_socket_factory()
            requests = []
            for rtype in record_types:
                request = dnsmessage.make_query(domain, rtype)
                requests.append(self.send_request(request, nameserver))
            responses = await asyncio.gather(*requests)
            for i, rtype in enumerate(record_types):
                response_data = responses[i]
                # If any query timed out return no records
                if response_data['rcode'] == "timeout":
                    rcodes['timeout'] = True
                    return {"records":"","rcodes":rcodes}
                # Otherwise compile request responses
                rcodes[rtype] = response_data['rcode']
                records += response_data['records']
        else:
            rcodes['timeout'] = True
        return {
            "records":"\n".join([record.to_text() for record in records]),
            "rcodes":rcodes
        }
    
    async def query(self, domain,nameserver,record_types=("NS","A","AAAA")):
        logger.debug(f"Query {domain} at {nameserver} for {record_types}")
        # Create hashable key from query args
        query_args_str = f"{domain}${nameserver}${'-'.join(record_types)}"
        # If query results are in LRU Cache, return cached results
        if self.query_cache.has(query_args_str):
            logger.debug(f"Cache found of {domain} at {nameserver} for {record_types}")
            return self.query_cache.get(query_args_str)
        # If same query is currently being made, wait for that query
        # to finish and return the results
        # Else start new query and create event to block any other 
        # identical queries that are made while this one finished executing
        if query_args_str in self.active_queries:
            logger.debug(f"Query of {domain} at {nameserver} for {record_types} already started")
            query_event = self.active_queries[query_args_str]
            await query_event.wait()
            return self.query_cache.get(query_args_str)
        else:
            logger.debug(f"Starting query of {domain} at {nameserver} for {record_types}")
            self.active_queries[query_args_str] = asyncio.Event()
            raw_response = await self.dns_response(domain,nameserver)
        response = raw_response['records'].splitlines()
        # Return dns response as dict
        data = {}
        for row in response:
            filtered_row = row.split()
            # Index by returned result
            if filtered_row[3] in record_types or "ANY" in record_types:
                data[filtered_row[4]]={
                    "name":filtered_row[0],
                    "ttl":filtered_row[1],
                    "class":filtered_row[2],
                    "type":filtered_row[3],
                    "data":filtered_row[4],
                }
        parsed_response = {
            "data":data, 
            "rcodes":raw_response['rcodes'],
            "domain":domain,
            "nameserver":nameserver
        }
        # Store latest query results in lru cache
        self.query_cache.set(query_args_str, parsed_response)
        # Unblock any concurrent identical results
        self.active_queries[query_args_str].set()
        # Remove query from active queries
        del self.active_queries[query_args_str]
        return parsed_response

    async def query_root(self, domain,record_types=("NS","A","AAAA")):
        root_nameserver = choice(list(constants.ROOT_SERVERS.values()))
        return await self.query(domain,root_nameserver,record_types)