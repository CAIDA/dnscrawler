from dns import asyncquery as dnsquery, message as dnsmessage, rdatatype
from random import choice
from functools import lru_cache
from ipaddress import ip_address
from collections import defaultdict
from async_lru import alru_cache
import socket
import socks
import asyncio
import sys

if __name__ == "pydns":
    import constants
    from logger import log
else:
    from . import constants
    from .logger import log

async def send_request(request, nameserver, retries=0):
    try:  
        response_data = await dnsquery.udp(q=request, where=nameserver, timeout=float(constants.REQUEST_TIMEOUT)) 
        rcode = response_data.rcode()
        records = response_data.answer + response_data.additional + response_data.authority
        return{"rcode":rcode, "records":records}
    except:
        # Query Timeout
        if retries < int(constants.REQUEST_TRIES):
            return await send_request(request, nameserver, retries+1)
        else:
            return {"rcode":"timeout", "records":[]}

class PyDNS:
    def __init__(self, socket_factories, ipv4_only=False):
        self.socket_factories = [socket.socket] + [self.create_socket_factory(factory['addr'], factory['port']) for factory in socket_factories];
        self.only_default_factory = len(self.socket_factories) == 1
        self.ipv4_only = ipv4_only

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

    async def dns_response(self, domain,nameserver,retries=0):
        record_types = (rdatatype.NS, rdatatype.A, rdatatype.AAAA)
        records = []
        rcodes = {}
        # If ipv4_only flag set, return timeout for all ipv6 queries
        if not self.ipv4_only or ip_address(nameserver).version == 4:
            dnsquery.socket_factory = self.get_socket_factory()
            requests = []
            for rtype in record_types:
                request = dnsmessage.make_query(domain, rtype)
                requests.append(send_request(request, nameserver))
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
        
    @alru_cache(maxsize=128)
    async def query(self, domain,nameserver,record_types=("NS","A","AAAA")):
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
        return {
            "data":data, 
            "rcodes":raw_response['rcodes'],
            "domain":domain,
            "nameserver":nameserver
        }

    @alru_cache(maxsize=128)
    async def query_root(self, domain,record_types=("NS","A","AAAA")):
        root_nameserver = choice(list(constants.ROOT_SERVERS.values()))
        return await self.query(domain,root_nameserver,record_types)