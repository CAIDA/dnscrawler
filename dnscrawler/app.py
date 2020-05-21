from .pydns import query_root,query
from .logger import log,log_records
import tldextract
# Get all zone data for a domain
def zone_data(ns, mappedDomains=None, root=True, isTLD=False):
    # print(ns)
    if(mappedDomains == None):
        mappedDomains = dict()
    ns = ns.lower()
    ext = tldextract.extract(ns)
    # Seperate domain into tld and domain name
    suffixparts = get_parts_from_name(ext.suffix)
    suffixparts.append(ext.domain)
    # DIG formats all names with trailing .
    tld = suffixparts[0]+"."
    if tld not in mappedDomains:
        mappedDomains[tld] = {
            "type":"tld"
        }
        mappedDomains[tld]["data"] = get_tld_data(tld)
    tld_data = mappedDomains[tld]["data"]
    # Get data for tld nameserver domains
    for record in [record for record in tld_data.values() if record['type']=="NS"]:
        record_ext = tldextract.extract(record["data"])
        nameserver_domain = record_ext.domain+"."+record_ext.suffix
        if nameserver_domain not in mappedDomains:
            # Pre initialize to prevent infinite loop
            mappedDomains[nameserver_domain] = {
                "type":"tld"
            }
            # Use isTLD flag to avoid adding data for any nameservers of a tld nameserver
            mappedDomains[nameserver_domain]["data"] = zone_data(nameserver_domain,mappedDomains,False,True)

    # If domain is only a tld, only return tld data
    if len(ext.domain) == 0:
        return list(tld_data.values())
    domain = tld
    domain_data = tld_data
    for i in range(1,len(suffixparts)):
        newDomain = suffixparts[i]+"."+domain
        # Get nameservers and ips for domain from tld nameserver ips
        full_tld_data = {
            "tld":domain,
            "tld_data":domain_data
        }
        domain = newDomain
        domain_data = get_domain_data(domain,full_tld_data)
    # Get data for all nameserver domains
    for record in [record for record in domain_data.values() if record['type']=="NS"]:
        record_ext = tldextract.extract(record["data"])
        nameserver_domain = record_ext.domain+"."+record_ext.suffix
        if nameserver_domain not in mappedDomains:
            # Pre initialize to prevent infinite loop
            mappedDomains[nameserver_domain] = {
                "type":"tld" if isTLD else "nameserver"
            }
            mappedDomains[nameserver_domain]["data"] = zone_data(nameserver_domain,mappedDomains,False)
    # Once returned to root recombine all mappedDomains data
    if root:
        for mapped_domain_data in mappedDomains.values():
            # Read all data except for tld data
            if mapped_domain_data['type']=="nameserver":
                # Only add A/AAAA record if tld for 'name' is same as original tld
                for record in mapped_domain_data['data'].values():
                    if record['type']=="NS" or get_parts_from_name(record['name'])[0]+"."==tld:
                        domain_data.update({
                            record['name']:record
                        })
    return domain_data


def print_zone_data(domain):
    log_records(list(zone_data(domain).values()))

def print_zone_json(domain):
    log(list(zone_data(domain).values()))

# Get authoritative nameservers for a tld
def get_tld_data(tld):
    tld_data = {}
    record_types = ("NS","A","AAAA")
    # Get nameservers and ips for tld root servers
    root_response = query_root(tld,record_types)
    tld_data.update(root_response)
    # Get nameservers and ips for tld from tld nameservers
    for record in root_response.values():
        if record['type']=="A":
            tldQuery = query(tld,record['data'],record_types)
            # Get tld nameservers from each authoritative tld nameserver
            tld_data.update(tldQuery)
    return tld_data
# Get authoritative nameservers from non tld domain
def get_domain_data(domain, full_tld_data):
    record_types = ("NS","A","AAAA")
    tld = full_tld_data["tld"]
    tld_data = full_tld_data["tld_data"]
    domain_data = {}
    tld_nameservers = [record['data'].lower() for record in tld_data.values() if record['name']==tld]
    tld_ips = [record['data'] for record in tld_data.values() if record['name'].lower() in tld_nameservers 
        and record['type'].upper() in ["A","AAAA"]]
    for nameserver_ip in tld_ips:
        domainQuery = query(domain,nameserver_ip,record_types)
        # log(domainQuery)
        domain_data.update(domainQuery)
    return domain_data
# Split up name by period
def get_parts_from_name(name):
    parts = [part for part in name.strip().split('.') if len(part)>0]
    parts.reverse()
    return parts