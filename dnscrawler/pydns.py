from dns import query as dnsquery, message as dnsmessage, rdatatype
from random import choice
from . import constants
from .logger import log
from functools import lru_cache

def dns_response(domain,nameserver,retries=0):
    try:  
        request = dnsmessage.make_query(domain, rdatatype.ANY)
        response_data = dnsquery.udp(request, nameserver, float(constants.REQUEST_TIMEOUT))
        records = response_data.answer + response_data.additional + response_data.authority
    except:
        if retries < int(constants.REQUEST_TRIES):
            return dns_response(domain,nameserver,retries+1)
        else:
            return ""
    return "\n".join([record.to_text() for record in records])
def query(domain,nameserver,record_types):
    raw_response = dns_response(domain,nameserver)
    response = raw_response.splitlines()
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
    return data

@lru_cache(maxsize=128)
def query_root(domain,record_types):
    root_nameserver = choice(list(constants.ROOT_SERVERS.values()))
    return query(domain,root_nameserver,record_types)