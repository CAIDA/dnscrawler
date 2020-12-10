from dns import asyncquery as dnsquery, message as dnsmessage, rdatatype
from random import choice
from functools import lru_cache
from ipaddress import ip_address
import socket
import socks

if __name__ == "pydns":
    import constants
    from logger import log
else:
    from . import constants
    from .logger import log

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
        if not self.ipv4_only or ip_address(nameserver).version == 4:
            dnsquery.socket_factory = self.get_socket_factory()
            for rtype in record_types:
                try:  
                    request = dnsmessage.make_query(domain, rtype)
                    response_data = await dnsquery.udp(q=request, where=nameserver, timeout=float(constants.REQUEST_TIMEOUT))
                    rcodes[rtype] = response_data.rcode()
                    records += response_data.answer + response_data.additional + response_data.authority
                except:
                    if retries < int(constants.REQUEST_TRIES):
                        return await self.dns_response(domain,nameserver,retries+1)
                    else:
                        rcodes['timeout'] = True
                        return {"records":"","rcodes":rcodes}
        else:
            rcodes['timeout'] = True
        return {
            "records":"\n".join([record.to_text() for record in records]),
            "rcodes":rcodes
        }
        
    # @lru_cache(maxsize=128)
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
        return {
            "data":data, 
            "rcodes":raw_response['rcodes'],
            "domain":domain,
            "nameserver":nameserver
        }

    # @lru_cache(maxsize=128)
    async def query_root(self, domain,record_types=("NS","A","AAAA")):
        root_nameserver = choice(list(constants.ROOT_SERVERS.values()))
        return self.query(domain,root_nameserver,record_types)