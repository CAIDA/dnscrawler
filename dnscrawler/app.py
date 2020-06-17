from .pydns import query_root,query
from .logger import log,log_records
import tldextract
from itertools import chain
# Get all zone data for a domain
def zone_data(ns, mappedDomains=None, root=True, isTLD=False, hazardous_domains=None):
    # If mappedDomains (cache of all zone data) is null, initialize dict (done at beginning)
    if(mappedDomains == None):
        mappedDomains = dict()
    # If hazardous_domains (set of all hazarous domain) is null, initialize dict (done at beginning)
    if(hazardous_domains == None):
        hazardous_domains = set()
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
            mappedDomains[nameserver_domain]["data"] = zone_data(nameserver_domain,mappedDomains,False,True,hazardous_domains)['domain_data']

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
        # Dont query if nameserver is sld
        if len([record for record in domain_data.values() if record['name']==domain]) == 0:
            domain_data = get_domain_data(domain,full_tld_data,mappedDomains)
            if len([record for record in domain_data.values() if record['type']=="NS"]) == 0:
                hazardous_domains.add(domain)
    # Get data for all nameserver domains
    for record in [record for record in domain_data.values() if record['type']=="NS"]:
        record_ext = tldextract.extract(record["data"])
        nameserver_domain = record_ext.domain+"."+record_ext.suffix
        if nameserver_domain not in mappedDomains:
            # Pre initialize to prevent infinite loop
            mappedDomains[nameserver_domain] = {
                "type":"tld" if isTLD else "nameserver"
            }
            mappedDomains[nameserver_domain]["data"] = zone_data(nameserver_domain,mappedDomains,False,False,hazardous_domains)['domain_data']
    # Once returned to root recombine all mappedDomains data
    if root:
        for mapped_domain_data in mappedDomains.values():
            # Read all data except for tld data
            if mapped_domain_data['type']=="nameserver":
                # Only add A/AAAA record if tld for 'name' is same as original tld
                domain_data.update(mapped_domain_data['data'])
    return {
        "domain_data":domain_data,
        "filtered_data":filter_domain_data(domain_data),
        "hazardous_domains":hazardous_domains
    }


def print_zone_data(domain):
    log_records(list(zone_data(domain)["domain_data"].values()))

def print_zone_json(domain):
    log(list(zone_data(domain)["domain_data"].values()))
def get_domain_dict(domain):
    domain_data = zone_data(domain)
    domain_data['filtered_data'].update({
        "hazardous_domains":list(domain_data['hazardous_domains'])
    })
    return {
        domain:domain_data['filtered_data']
    }
# Get authoritative nameservers for a tld
def get_tld_data(tld):
    tld_data = {}
    record_types = ("NS","A","AAAA")
    # Get nameservers and ips for tld root servers
    root_response = query_root(tld,record_types)
    tld_data.update(root_response)
    # Get nameservers and ips for tld from tld nameservers
    for record in root_response.values():
        if record['type']=="A" or record['type']=="AAAA":
            tldQuery = query(tld,record['data'],record_types)
            # Get tld nameservers from each authoritative tld nameserver
            tld_data.update(tldQuery)
    return tld_data
# Get authoritative nameservers from non tld domain
def get_domain_data(domain, full_tld_data,mappedDomains):
    record_types = ("NS","A","AAAA")
    tld = full_tld_data["tld"]
    tld_data = full_tld_data["tld_data"]
    domain_data = {}
    # Get all records from mapped data
    mapped_data = list(chain.from_iterable([domain['data'].values() for domain in mappedDomains.values() if "data" in domain]))
    # Get nameservers from ns records
    tld_nameservers = set([record['data'].lower() for record in tld_data.values() if record['name']==tld and record['type']=="NS"])
    # Make a dictionary of nameservers and ips; if any nameserver doesnt have an ip, recurse to get ip data
    nameserver_data ={}
    for nameserver in tld_nameservers:
        nameserver_data[nameserver.lower()] = []
    for record in mapped_data:
        name=record['name'].lower()
        if name in nameserver_data and record['type'].upper() in ["A","AAAA"]:
            nameserver_data[name].append(record['data'])
    # Check if any ns doesnt have ips
    nameserver_ips = set(chain.from_iterable(nameserver_data.values()))

    for ip in nameserver_ips:
        domainQuery = query(domain,ip,record_types)
        # log(domainQuery)
        domain_data.update(domainQuery)
    return domain_data
# Split up name by period
def get_parts_from_name(name):
    parts = [part for part in name.strip().split('.') if len(part)>0]
    parts.reverse()
    return parts
# Split up domain data into nameservers, tlds, ips, slds
def filter_domain_data(domain_data):
    nameservers = set()
    tlds = set()
    ipv6 = set()
    ipv4 = set()
    tlds = set()
    slds = set()
    for record in domain_data.values():
        if record['type'] == "A":
            ipv4.add(record['data'])
        elif record['type'] == "AAAA":
            ipv6.add(record['data'])
        elif record['type'] == "NS":
            nameservers.add(record['data'])
            ns_ext = tldextract.extract(record['data'])
            tlds.add(ns_ext.suffix)
            slds.add(ns_ext.domain+"."+ns_ext.suffix)
    return {
        "nameservers":list(nameservers),
        "ipv4":list(ipv4),
        "ipv6":list(ipv6),
        "tlds":list(tlds),
        "slds":list(slds),
    }
