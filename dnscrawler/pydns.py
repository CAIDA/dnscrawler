from collections import defaultdict, namedtuple
from ipaddress import ip_address
import logging
import math
import os
from random import choice, random
import socket
import sys
import time
from typing import Callable

import socks
import asyncio
from dns import asyncquery as dnsquery, message as dnsmessage, rdatatype

import dnscrawler.constants as constants
from dnscrawler.asynciobackend import Backend
from dnscrawler.lrucache import LRUCache
from dnscrawler.ratelimiter import RateLimiter
from dnscrawler.contextmanager import AsyncContextManager


logger = logging.getLogger(__name__)


DNSRecord = namedtuple('DNSRecord', ["name", "ttl", "rrclass", "rrtype", "data"])
QueryResponse = namedtuple('QueryResponse', ["data", "rcodes", "domain", "nameserver"])
SOCKSProxy = namedtuple('SOCKSProxy', ['addr', 'port'])

class PyDNS(AsyncContextManager):
    '''PyDNS handles scheduling and sending DNS queries concurrently
    
    Args:
        socket_factories (optional): Defaults to empty list. List of
            SOCKSProxy tuples containing the ip address and port of a
            SOCKS5 proxy which queries can be routed through.
        ipv4_only (optional): Defaults to False. If True, resolver will
                only send queries to ipv4 nameservers to avoid ipv6
                timeouts.

    Attributes:
        socket_factories (list): List of factory functions that return
            a SOCK5 proxied socket
        ipv4_only (bool): If True, resolver will only send queries to 
            ipv4 nameservers to avoid ipv6 timeouts.
        requests_sent (int): Total number of dns requests sent. This 
            number is updated immediately before the request is sent.
        min_requests_per_second (int): Minimum number of requests sent
            in one second. This number only reflects the number of 
            queries sent in one second windows where atleast one query
            is sent.
        max_requests_per_second (int): Maximum number of requests sent
            in one second. This number only reflects the number of 
            queries sent in one second windows where atleast one query
            is sent.
        avg_requests_per_second (int): Average number of requests sent
            in one second. This number only reflects the number of 
            queries sent in one second windows where atleast one query
            is sent.
        request_measurement_count (int): Number of times the number of
            requests were measured, equivalent to the number of seconds
            where atleast one request was sent.
        awaiting_rps_calc (bool): Flag to detect if a requests per
            second measurement is already in progress. If False, a new
            request per second measurement will be started.
        timeout_nameservers (set): Collection of nameservers which have
            timed out repeatedly. Any further requests to these 
            nameservers will be assumed to automatically timeout, and
            will not be sent.
        active_requests (defaultdict(list)): Stores each started request
            in a list indexed by nameserver. Used to cancel all active
            requests for nameservers which timeout repeatedly.
        active_queries (dict): Tracks all active queries being made. 
            Used to avoid sending multiple indentical queries in 
            succession by waiting for the first one complete and using 
            its cached results.
        nameserver_ratelimiters (dict): Stores a ratelimiter for each
            nameserver that operates on requests per second rather than
            number of concurrent requests.
        MAX_CACHED_QUERIES (int): The maximum number of queries cache.
        MAX_CONCURRENT_REQUESTS (int): The maximum number of requests to
            have open at any given point of time.
        MAX_REQUESTS_PER_NAMESERVER_SECOND (int): Maximum number of 
            requests to start to a non-tld nameserver in a second.
        MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND (int): Maximum number of 
            requests to start to an authoritative nameservers for a tld 
            or public suffix tld in a second.
        query_cache (LRUCache): An LRU cache of prior queries
        tld_nameserver_ips (list): List of ip addresses for the
            authoritative nameservers for most tlds or public suffix 
            tlds.
    '''
    def __init__(self, socket_factories:list = [], ipv4_only:bool = False):
        super().__init__()
        custom_socket_factories = [self.create_socket_factory(proxy.addr, proxy.port)
            for proxy in socket_factories]
        self.socket_factories = [socket.socket] + custom_socket_factories
        self.ipv4_only = ipv4_only
        self.requests_sent = 0
        self.min_requests_per_second = math.inf
        self.max_requests_per_second = 0
        self.avg_requests_per_second = 0
        self.request_measurement_count = 0
        self.awaiting_rps_calc = False
        self.timeout_nameservers = set()
        self.active_requests = defaultdict(list)
        self.active_queries = {}
        self.nameserver_ratelimiters = {}
        query_limiter_attributes = [
            "MAX_CACHED_QUERIES",
            "MAX_CONCURRENT_REQUESTS",
            "MAX_REQUESTS_PER_NAMESERVER_SECOND",
            "MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND",
        ]
        # Pull default values for query limiter attributes from 
        # constants module
        for field in query_limiter_attributes:
            setattr(self,field, getattr(constants, field))
        self.query_cache = LRUCache(self.MAX_CACHED_QUERIES)
        # Load list of public suffix ips
        self.tld_nameserver_ips = []
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(f"{dir_path}/public_suffix_ips.txt", "r") as ps_tld_ip_file:
            for row in ps_tld_ip_file:
                ip = row.strip().lower()
                self.tld_nameserver_ips.append(ip)

    async def __aenter__(self):
        '''Initialize concurrent request limiter'''
        self.concurrent_request_limiter = asyncio.Semaphore(self.MAX_CONCURRENT_REQUESTS)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        '''Wait for all rps measurements to finish and for all
        ratelimiters to close.
        '''
        for ratelimiter in self.nameserver_ratelimiters.values():
            ratelimiter_exit_task = asyncio.create_task(
                ratelimiter.__aexit__(exc_type, exc, tb))
            self.awaitable_list.append(ratelimiter_exit_task)
        await super().__aexit__(exc_type, exc, tb)

    def create_socket_factory(self, addr:str, port:str) -> Callable:
        '''Create a SOCKS5 proxied socket factory

        Args:
            addr: IP address of the SOCKS5 proxy.
            port: Port of the SOCKS5 proxy.

        Returns:
            Factory function for SOCKS5 proxied sockets.
        '''
        def socket_factory(
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                proto=0,
                fileno=None):
            s = socks.socksocket(family, type, proto, fileno)
            s.set_proxy(proxy_type=socks.SOCKS5, addr=addr, port=port)
            return s
        return socket_factory

    def get_socket_factory(self) -> Callable:
        ''' Get a random socket factory

        Returns:
             Factory function for SOCKS5 proxied sockets.
        '''
        if len(self.socket_factories) == 1:
            return self.socket_factories[0]
        else:
            return choice(list(self.socket_factories))

    def stats(self) -> dict:
        '''Get stats about the amount of queries and requests made
        
        Returns:
            Dict containing query and requests stats
        '''
        # Compile the stats for each nameserver ratelimiter
        ratelimiter_data = []
        for nameserver, ratelimiter in self.nameserver_ratelimiters.items():
            stats = ratelimiter.stats()
            stats["name"] = nameserver
            ratelimiter_data.append(stats)
        # Sort ratelimiters by number of requests sent
        ratelimiter_data.sort(key=lambda x: x['action_count'], reverse=True)
        return {
            "MAX_CACHED_QUERIES": self.MAX_CACHED_QUERIES,
            "MAX_CONCURRENT_REQUESTS": self.MAX_CONCURRENT_REQUESTS,
            "MAX_REQUESTS_PER_NAMESERVER_SECOND": self.MAX_REQUESTS_PER_NAMESERVER_SECOND,
            "MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND": self.MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND,
            "min_requests_per_second": self.min_requests_per_second,
            "max_requests_per_second": self.max_requests_per_second,
            "avg_requests_per_second": self.avg_requests_per_second,
            "query_cache": self.query_cache.stats(),
            "nameserver_ratelimiters": ratelimiter_data[:constants.MAX_RETURNED_RATELIMITER_STATS]
        }

    async def calculate_rps(self):
        '''Update the stats on the number of requests per second'''
        # Get the number of requests made at the beginning of the window
        current_period_starting_requests = self.requests_sent
        # Wait one second
        await asyncio.sleep(1)
        # Increment the number of measurement made prior to measuring
        self.request_measurement_count += 1
        # Get the number of requests mad at the end of the window
        current_period_ending_requests = self.requests_sent
        requests_per_second = current_period_ending_requests - current_period_starting_requests
        self.max_requests_per_second = max(self.max_requests_per_second, requests_per_second)
        self.min_requests_per_second = min(self.min_requests_per_second, requests_per_second)
        # To calculate the average requests per second, divide the
        # closing number of measurements at the end of the period by
        # the number of measurements (one measurement per second of 
        # querying)
        self.avg_requests_per_second = current_period_ending_requests \
            / self.request_measurement_count
        self.awaiting_rps_calc = False

    async def send_request(
        self, 
        request:dnsmessage, 
        nameserver:str, 
        retries:int = 0
    ):
        '''Send a DNS request to a nameserver
        
        Args:
            request: The dns query to send to the nameserver.
            nameserver: Nameserver to query.
            retries: Number of times the request has timed out.
        '''
        question = request.question[0]
        domain = question.name
        rdtype_text = rdatatype.to_text(question.rdtype)
        block_nameserver = False
        response = {"rcode": "timeout", "records": []}
        # Multiply timeout duration by n each iteration (ie. if 
        # multiplier is 5, timeouts would be 2s, 10s, 50s, etc).
        current_timeout_multiplier = constants.TIMEOUT_MULTIPLIER ** retries
        current_potential_timeout =  constants.REQUEST_TIMEOUT * current_timeout_multiplier
        request_timeout = min(current_potential_timeout, constants.MAX_TIMEOUT)
        # Return timeout for all nameservers that have previously timed out
        if nameserver not in self.timeout_nameservers:
            logger.debug(
                f"Starting {rdtype_text} request to {nameserver} for {domain}")
            # Restrict number of concurrent requests to prevent
            # packet loss and avoid rate limiting
            if self.concurrent_request_limiter.locked():
                logger.debug(
                    "Waiting to send request: concurrent request limit hit")
            await self.concurrent_request_limiter.acquire()
            # Begin calculating rps if not started
            if not self.awaiting_rps_calc:
                self.awaiting_rps_calc = True
                self.awaitable_list.append(
                    asyncio.create_task(self.calculate_rps()))
            # Flag to detect if requests succeeded
            request_success = False
            try:
                query_request = dnsquery.udp(
                    q=request, 
                    where=nameserver, 
                    backend=Backend()
                )
                query_coro = asyncio.wait_for(
                    query_request, timeout=request_timeout)
                query_task = asyncio.create_task(query_coro)
                self.awaitable_list.append(query_task)
                # Add request future to active_requests
                self.active_requests[nameserver].append(query_task)
                self.requests_sent += 1
                response_data = await query_task
                request_success = True
                # Remove request future from active_requests
                self.active_requests[nameserver].remove(query_task)
                rcode = response_data.rcode()
                records = response_data.answer + response_data.additional + response_data.authority
                response = {"rcode": rcode, "records": records}
            except ConnectionRefusedError as err:
                logger.warning(
                    f"Skipping future requests to {nameserver} due to ConnectionRefusedError")
                block_nameserver = True
            except ConnectionResetError as err:
                logger.warning(
                    f"Skipping future requests to {nameserver} due to ConnectionResetError")
                block_nameserver = True
            except Exception:
                # Query Timeout
                if retries > constants.REQUEST_RETRIES:
                    logger.warning(
                        f"Skipping future requests to {nameserver} due to repeated timeout")
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
                    response = await ns_ratelimiter.run(self.send_request(request, nameserver, retries + 1))
        else:
            logger.debug(
                f"Request to {nameserver} skipped due to prior timeout")
        return response

    async def dns_request(self, domain, nameserver, record_types):
        logger.debug(f"Preparing request to {nameserver} for {domain}")
        records = []
        rcodes = {}
        # If ipv4_only flag set, return timeout for all ipv6 queries
        # Return timeout for all nameservers that have previously timed out
        if (not self.ipv4_only or ip_address(nameserver).version ==
                4) and nameserver not in self.timeout_nameservers:
            dnsquery.socket_factory = self.get_socket_factory()
            requests = []
            for rdtype_text in record_types:
                request = dnsmessage.make_query(
                    domain, rdatatype.from_text(rdtype_text))
                # Run request ratelimited by nameserver
                if nameserver not in self.nameserver_ratelimiters:
                    max_actions = self.MAX_REQUESTS_PER_TLD_NAMESERVER_SECOND if nameserver.lower(
                    ) in self.tld_nameserver_ips else self.MAX_REQUESTS_PER_NAMESERVER_SECOND
                    # Create ratelimiter if not exists
                    ns_ratelimiter = RateLimiter(max_actions=max_actions)
                    await ns_ratelimiter.__aenter__()
                    self.nameserver_ratelimiters[nameserver] = ns_ratelimiter
                else:
                    ns_ratelimiter = self.nameserver_ratelimiters[nameserver]
                if ns_ratelimiter.ratelimit_hit():
                    logger.warning(f"Request ratelimit hit for {nameserver}")
                requests.append(ns_ratelimiter.run(
                    self.send_request(request, nameserver)))
            responses = await asyncio.gather(*requests)
            for i, rdtype_text in enumerate(record_types):
                response_data = responses[i]
                # If any query timed out return no records
                if response_data['rcode'] == "timeout":
                    rcodes['timeout'] = True
                    return {"records": "", "rcodes": rcodes}
                # Otherwise compile request responses
                rcodes[rdtype_text] = response_data['rcode']
                records += response_data['records']
        else:
            rcodes['timeout'] = True
        return {
            "records": "\n".join([record.to_text() for record in records]),
            "rcodes": rcodes
        }

    async def query(self, domain, nameserver, record_types=("NS", "A", "AAAA")):
        logger.debug(f"Query {domain} at {nameserver} for {record_types}")
        # Create hashable key from query args
        query_args_str = f"{domain}${nameserver}${'-'.join(record_types)}"
        # If query results are in LRU Cache, return cached results
        cached_results = self.query_cache.get(query_args_str)
        if cached_results is not None:
            logger.debug(
                f"Cache found of {domain} at {nameserver} for {record_types}")
            return cached_results
        # If same query is currently being made, wait for that query
        # to finish and return the results
        # Else start new query and create event to block any other
        # identical queries that are made while this one finished executing
        if query_args_str in self.active_queries:
            logger.debug(
                f"Query of {domain} at {nameserver} for {record_types} already started")
            query_event = self.active_queries[query_args_str]
            await query_event.wait()
            return self.query_cache.get(query_args_str)
        else:
            logger.debug(
                f"Starting query of {domain} at {nameserver} for {record_types}")
            self.active_queries[query_args_str] = asyncio.Event()
            raw_response = await self.dns_request(domain, nameserver, record_types)
        response = raw_response['records'].splitlines()
        rcodes = raw_response['rcodes']
        # Collect valid records in set to remove duplicates
        data = set()
        for row in response:
            record = DNSRecord._make(row.split()[:5])
            # Index by returned result
            if record.rrtype in record_types or "ANY" in record_types:
                data.add(record)
        # Cast data records set as list to make it JSON serializable
        data = list(data)
        parsed_response = QueryResponse(data, rcodes, domain, nameserver)
        # Store latest query results in lru cache
        self.query_cache.set(query_args_str, parsed_response)
        # Unblock any concurrent identical results
        self.active_queries[query_args_str].set()
        # Remove query from active queries
        del self.active_queries[query_args_str]
        return parsed_response
