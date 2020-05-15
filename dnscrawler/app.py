from .pydns import query_root,query
from .logger import log,log_records
def zone_data(domain):
    # Seperate domain into tld and domain name
    parts = [part for part in domain.strip().split('.') if len(part)>0]
    parts.reverse()
    # DIG formats all names with trailing .
    tld = parts[0]+"."
    domain = parts[1]+"."+parts[0]+"."
    zone_data = {}
    record_types = ("NS","A")
    # Get nameservers and ips for tld root servers
    root_response = query_root(tld,record_types)
    zone_data.update(root_response)
    # Get nameservers and ips for tld from tld nameservers
    for record in root_response.values():
        if record['type']=="NS":
            # Get tld nameservers from each authoritative tld nameserver
            zone_data.update(query(tld,record['data'],record_types))
    # Get nameservers and ips for domain from tld nameserver ips
    domain_data = {}
    zone_nameservers = [record['data'] for record in zone_data.values() if record['name']==tld]
    zone_ips = [record['data'] for record in zone_data.values() if record['name'] in zone_nameservers 
        and record['type'] in ["A","AAAA"]]
    for nameserver_ip in zone_ips:
        domain_data.update(query(domain,nameserver_ip,["NS","A","AAAA"]));
    return list(domain_data.values());

def print_zone_data(domain):
    log_records(zone_data(domain))

def print_zone_json(domain):
    log(zone_data(domain))