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
import os
import logging 

if __name__ == "pydns":
    import constants
    from asynciobackend import Backend
    from lrucache import LRUCache
    from ratelimiter import RateLimiter
    from .contextmanager import AsyncContextManager
else:
    from . import constants
    from .asynciobackend import Backend
    from .lrucache import LRUCache
    from .ratelimiter import RateLimiter
    from .contextmanager import AsyncContextManager


logger = logging.getLogger(__name__)

class PyDNS(AsyncContextManager):
    def __init__(
        self, 
        socket_factories, 
        ipv4_only=False, 
        MAX_CONCURRENT_REQUESTS = None, 
        MAX_CACHED_QUERIES=None,
        MAX_REQUESTS_PER_NAMESERVER_SECOND=None,
        MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND=None
    ):
        super().__init__()
        self.socket_factories = [socket.socket] + [self.create_socket_factory(factory['addr'], factory['port']) for factory in socket_factories]
        self.only_default_factory = len(self.socket_factories) == 1
        self.ipv4_only = ipv4_only
        # Total number of queries sent
        self.requests_sent = 0
        # Min, max, and avg requests per second
        self.min_requests_per_second = math.inf
        self.max_requests_per_second = 0
        self.avg_requests_per_second = 0
        self.request_measurement_count = 0
        self.awaiting_rps_calc = False
        # Set of nameservers to auto timeout all queries to
        self.timeout_nameservers = set()
        self.active_requests = defaultdict(list)
        self.active_queries = {}
        self.nameserver_ratelimiters = {}
        self.MAX_CACHED_QUERIES = MAX_CACHED_QUERIES or constants.MAX_CACHED_QUERIES
        self.MAX_CONCURRENT_REQUESTS = MAX_CONCURRENT_REQUESTS or constants.MAX_CONCURRENT_REQUESTS
        self.MAX_REQUESTS_PER_NAMESERVER_SECOND = MAX_REQUESTS_PER_NAMESERVER_SECOND or constants.MAX_REQUESTS_PER_NAMESERVER_SECOND
        self.MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND = MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND or constants.MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND
        self.query_cache = LRUCache(self.MAX_CACHED_QUERIES)
        self.awaitable_list = []
        self.tld_nameserver_ips = []
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(f"{dir_path}/public_suffix_ips.txt", "r") as ps_tld_ip_file:
            for row in ps_tld_ip_file:
                ip = row.strip().lower()
                self.tld_nameserver_ips.append(ip)

    async def __aenter__(self):
        self.concurrent_request_limiter = asyncio.Semaphore(self.MAX_CONCURRENT_REQUESTS)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        for ratelimiter in self.nameserver_ratelimiters.values():
            ratelimiter_exit_task = asyncio.create_task(ratelimiter.__aexit__(exc_type, exc, tb))
            self.awaitable_list.append(ratelimiter_exit_task)
        await super().__aexit__(exc_type, exc, tb, __name__)


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

    def stats(self):
        ratelimiter_data = []
        for nameserver, ratelimiter in self.nameserver_ratelimiters.items():
            stats = ratelimiter.stats()
            stats["name"] = nameserver
            ratelimiter_data.append(stats)
        ratelimiter_data.sort(key=lambda x:x['action_count'], reverse=True)
        return {
            "MAX_CACHED_QUERIES":self.MAX_CACHED_QUERIES,
            "MAX_CONCURRENT_REQUESTS":self.MAX_CONCURRENT_REQUESTS,
            "MAX_REQUESTS_PER_NAMESERVER_SECOND":self.MAX_REQUESTS_PER_NAMESERVER_SECOND,
            "MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND":self.MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND,
            "min_requests_per_second":self.min_requests_per_second,
            "max_requests_per_second":self.max_requests_per_second,
            "avg_requests_per_second":self.avg_requests_per_second,
            "query_cache":self.query_cache.stats(),
            "nameserver_ratelimiters":ratelimiter_data[:constants.MAX_RETURNED_RATELIMITER_STATS]
        }

    async def calculate_rps(self):
        current_period_starting_requests = self.requests_sent
        await asyncio.sleep(1)
        current_period_ending_requests = self.requests_sent
        current_requests_per_second = current_period_ending_requests - current_period_starting_requests
        self.max_requests_per_second = max(self.max_requests_per_second, current_requests_per_second)
        self.min_requests_per_second = min(self.min_requests_per_second, current_requests_per_second)
        self.avg_requests_per_second = (self.request_measurement_count * self.avg_requests_per_second + \
            current_requests_per_second) / (self.request_measurement_count + 1)
        self.request_measurement_count += 1
        self.awaiting_rps_calc = False

    async def send_request(self, request, nameserver, retries=0):
        question = request.question[0]
        domain = question.name
        rdtype_text = rdatatype.to_text(question.rdtype)
        block_nameserver = False
        response = {"rcode":"timeout", "records":[]}
        # Multiply timeout duration by n each iteation (ie. if multiplier is 5, timeouts of 2s, 10s, 50s), 
        request_timeout = min(constants.REQUEST_TIMEOUT * (constants.TIMEOUT_MULTIPLIER ** retries), constants.MAX_TIMEOUT)
        # Return timeout for all nameservers that have previously timed out
        if nameserver not in self.timeout_nameservers:
            logger.debug(f"Starting {rdtype_text} request to {nameserver} for {domain}")
            # Restrict number of concurrent requests to prevent
            # packet loss and avoid rate limiting
            if self.concurrent_request_limiter.locked():
                logger.debug("Waiting to send request: concurrent request limit hit")
            await self.concurrent_request_limiter.acquire()
            # Begin calculating rps if not started
            if not self.awaiting_rps_calc:
                self.awaiting_rps_calc = True
                self.awaitable_list.append(asyncio.create_task(self.calculate_rps()))
            # Flag to detect if requests succeeded
            request_success = False
            try:
                query_request = dnsquery.udp(q=request, where=nameserver, backend=Backend())
                query_coro = asyncio.wait_for(query_request, timeout=request_timeout)
                query_task = asyncio.create_task(query_coro)
                self.awaitable_list.append(query_task)
                # Add request future to active_requests
                self.active_requests[nameserver].append(query_task)
                response_data = await query_task
                self.requests_sent +=1
                request_success = True
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
            except Exception:
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
                elif not request_success:
                    ns_ratelimiter = self.nameserver_ratelimiters[nameserver] 
                    response = await ns_ratelimiter.run(self.send_request(request, nameserver, retries+1))
        else:
            logger.debug(f"Request to {nameserver} skipped due to prior timeout")
        return response

    async def dns_response(self, domain,nameserver,record_types):
        logger.debug(f"Preparing request to {nameserver} for {domain}")
        records = []
        rcodes = {}
        # If ipv4_only flag set, return timeout for all ipv6 queries
        # Return timeout for all nameservers that have previously timed out
        if (not self.ipv4_only or ip_address(nameserver).version == 4) and nameserver not in self.timeout_nameservers:
            # dnsquery.socket_factory = self.get_socket_factory()
            requests = []
            for rdtype_text in record_types:
                request = dnsmessage.make_query(domain, rdatatype.from_text(rdtype_text))
                # Run request ratelimited by nameserver
                if nameserver not in self.nameserver_ratelimiters:
                    max_actions = self.MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND if nameserver.lower() \
                            in self.tld_nameserver_ips else self.MAX_REQUESTS_PER_NAMESERVER_SECOND 
                    # Create ratelimiter if not exists
                    ns_ratelimiter = RateLimiter(max_actions=max_actions)
                    await ns_ratelimiter.__aenter__()
                    self.nameserver_ratelimiters[nameserver] = ns_ratelimiter
                else:
                    ns_ratelimiter = self.nameserver_ratelimiters[nameserver]
                if ns_ratelimiter.ratelimit_hit():
                    logger.warning(f"Request ratelimit hit for {nameserver}")
                requests.append(ns_ratelimiter.run(self.send_request(request, nameserver)))
            responses = await asyncio.gather(*requests)
            for i, rdtype_text in enumerate(record_types):
                response_data = responses[i]
                # If any query timed out return no records
                if response_data['rcode'] == "timeout":
                    rcodes['timeout'] = True
                    return {"records":"","rcodes":rcodes}
                # Otherwise compile request responses
                rcodes[rdtype_text] = response_data['rcode']
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
        cached_results = self.query_cache.get(query_args_str)
        if cached_results is not None:
            logger.debug(f"Cache found of {domain} at {nameserver} for {record_types}")
            return cached_results
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
            raw_response = await self.dns_response(domain,nameserver,record_types)
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
