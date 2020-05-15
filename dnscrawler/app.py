import dig
from logger import log
def zone_data(domain):
    # Seperate domain into tld and domain name
    parts = [part for part in domain.strip().split('.') if len(part)>0]
    parts.reverse()
    # DIG formats all names with trailing .
    tld = parts[0]+"."
    domain = parts[1]+"."+parts[0]+"."
    zone_data = {}
    # Get nameservers and ips for tld root servers
    root_response = dig.query_root(tld,["NS","A"])
    zone_data.update(root_response)
    # Get nameservers and ips for tld from tld nameservers
    for record in root_response.values():
        if record['type']=="NS":
            # Get tld nameservers from each authoritative tld nameserver
            zone_data.update(dig.query(tld,record['data'],["NS","A"]))
    # Get nameservers and ips for domain from tld nameserver ips
    domain_data = {}
    zone_nameservers = [record['data'] for record in zone_data.values() if record['name']==tld]
    zone_ips = [record['data'] for record in zone_data.values() if record['name'] in zone_nameservers and 
        (record['type']=="A" or record['type'=="AAAA"])]
    for nameserver_ip in zone_ips:
        domain_data.update(dig.query(domain,nameserver_ip,["NS","A","AAAA"]));
    return domain_data;