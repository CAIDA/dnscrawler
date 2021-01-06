from collections import defaultdict
from functools import lru_cache
from random import choice
from tldextract import extract
from datetime import datetime, timezone
import os
import time
import asyncio
import logging

if __name__ == "__main__":
    import constants
    from logger import log
    from pydns import PyDNS
    from querysummary import QuerySummary
    from querysummarylist import QuerySummaryList
    from node import Node
    from nodelist import NodeList
else:
    from . import constants
    from .logger import log
    from .pydns import PyDNS
    from .querysummary import QuerySummary
    from .querysummarylist import QuerySummaryList
    from .node import Node
    from .nodelist import NodeList

logger = logging.getLogger(__name__)

class DNSResolver:
    # Get RFC 3339 timestamp
    @staticmethod
    def get_timestamp():
        timestamp = datetime.now(timezone.utc).astimezone()
        return timestamp.isoformat()

    # Create new dnsresolver
    # socket_factories - List of SOCKS5 proxies through which to route queries
    # ipv4_only - Only run queries to ipv4 nameservers to avoid ipv6 timeouts
    def __init__(self, socket_factories=[], ipv4_only=False):
        self.pydns = PyDNS(socket_factories, ipv4_only)
        self.ipv4_only = ipv4_only
        self.active_resolutions = set()
        self.past_resolutions = {}
        self.root_servers = {
            "a.root-servers.net.":{"198.41.0.4"},
            # "b.root-servers.net.":{"199.9.14.201"},
            # "c.root-servers.net.":{"192.33.4.12"},
            # "d.root-servers.net.":{"199.7.91.13"},
            # "e.root-servers.net.":{"192.203.230.10"},
            # "f.root-servers.net.":{"192.5.5.241"},
            # "g.root-servers.net.":{"192.112.36.4"},
            # "h.root-servers.net.":{"198.97.190.53"},
            # "i.root-servers.net.":{"192.36.148.17"},
            # "j.root-servers.net.":{"192.58.128.30"},
            # "k.root-servers.net.":{"193.0.14.129"},
            # "l.root-servers.net.":{"199.7.83.42"},
            # "m.root-servers.net.":{"202.12.27.33"},
        };
        self.xid_cache = {}
        self.nameservers = defaultdict(set, self.root_servers)

    async def __aenter__(self):
        await self.pydns.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.pydns.__aexit__(exc_type, exc, tb)

    # Return a random rootserver for querying
    def get_root_server(self):
        server = choice(list(self.root_servers))
        return {server:self.root_servers[server]}

    # Return the ips and ns records that are authoritative for a hostname
    # current_name -  The hostname to select NS records for, from a given DNS query
    # records - The results of a pydns query
    # output_dict - Dictionary to store all ns, tld, sld, ip, and hazardous_domain data,
    #               If not provided, parse will not attempt to recurse down for any missing ips
    # prefix - String indicating category of resolved hostnames, particulary if 
    #          the hostname came from resolving a public suffix dependency (ex. resolving co.uk)
    # is_ns - A flag to indicate that function call came from resolving a prior NS record
    async def parse(self, current_name, records, output_dict=None, prefix="", is_ns=False, current_node=None, node_list=None, node_trust_type="parent"):
        # Convert current_name to lower case for sake of uniformity
        current_name = current_name.lower()
        # Create dictionary to store all ips for each authoritative ns
        auth_ns = {}
        # Pull all nameservers for current_name into a set
        ns_set = set()
        # Pull all ip-ns pairs into a dict for comparison with ns_set
        ip_dict = self.nameservers
        # Map current node's nameservers to its nameserver nodes
        node_nameservers = {}
        # Flag to check if node is part of the resolution of a public suffix hostname for node type inference
        is_public_suffix = prefix=="ps_"
        for record in records:
            # Add all nameservers for names that are a substring of current_name to ns_set
            if record['type'] == 'NS' and record['name'].lower() in current_name:
                if record['name'].lower() == current_name:
                    record_nameserver_node = node_list.create_node(record['data'], Node.infer_node_type(record['data'], is_ns=True))
                    record_nameserver_node.is_public_suffix = is_public_suffix
                    node_nameservers[record['data']] = record_nameserver_node
                    if current_node:
                        current_node.trusts(record_nameserver_node, node_trust_type)
                # Convert data to lower case for sake of uniformity
                ns_set.add(record['data'].lower())
                # If output_dict is provided (not parsing tld data) then store the ns data in output_dict
                if output_dict is not None:
                    # Convert data to lower case for sake of uniformity
                    output_dict[prefix+'ns'].add(record['data'].lower())
            elif record['type'] in ('A','AAAA'):
                # Add all ips for a hostname to a set (ex. 'ns1.example.com':{1.1.1.0, 1.1.1.1})
                # Convert data to lower case for sake of uniformity
                ip_dict[record['name'].lower()].add(record['data'].lower())
                ip_version = 4 if record['type'] == 'A' else 6
                # If output_dict is provided (not parsing tld data) then store the ip data in output_dict
                if output_dict is not None:
                    # If A record then store in ipv4, else store in ipv6
                    if record['type'] == 'A':
                        # Convert data to lower case for sake of uniformity
                        output_dict[prefix+'ipv4'].add(record['data'].lower())
                    else:
                        # Convert data to lower case for sake of uniformity
                        output_dict[prefix+'ipv6'].add(record['data'].lower())
                    # If an A/AAAA record exists for the current name, add it straight to output_dict
                    # so that it can be parsed for tlds and slds
                    if record['name'].lower() == current_name:
                        record_ip_node = node_list.create_node(record['data'], Node.infer_node_type(record['data']))
                        record_ip_node.is_public_suffix = is_public_suffix
                        if current_node:
                            current_node.trusts(record_ip_node, node_trust_type)
                        output_dict[record['name'].lower()].add(record['data'].lower())
                        # If is_ns is true, query came from resolving a previous NS record, so the corresponding
                        # a record can be treated as a nameserver
                        if is_ns:
                            ns_set.add(current_name)
        # Compile sets of all ips for authoritative ns into auth_ns
        # Seperate ns_name and current_name by domain and suffix in order to avoid
        # reresolution if both the ns and the current_name belong to the same domain
        # (ie. don't reresolve ns1.example.com if current name is example.com)
        extracted_current = extract(current_name)
        current_name_parts = [part for part in extracted_current.domain.split('.')+extracted_current.suffix.split('.') if len(part) > 0]
        sanitized_current_name = f"{'.'.join(current_name_parts)}."
        for ns_name in ns_set:
            # If ns name is '.' skip further parsing for current iteration and
            # pass an empty set for ip addresses
            if ns_name == ".":
                auth_ns[ns_name] = {}
                continue
            extracted_ns = extract(ns_name)
            # Get sanitized name (domain + suffix) for checking if in active_resolutions
            ns_name_parts = [part for part in extracted_ns.domain.split('.')+extracted_ns.suffix.split('.') if len(part) > 0]
            sanitized_ns_name = f"{'.'.join(ns_name_parts)}."
            # Add TLD and SLD data to output_dict
            if output_dict is not None:
                # Add data for each ns
                if len(extracted_ns.domain) > 0:
                    output_dict[prefix+'sld'].add(f"{extracted_ns.domain}.{extracted_ns.suffix}.")
                    output_dict[prefix+'tld'].add(f"{extracted_ns.suffix}.")
                elif len(ns_name_parts) > 1:
                    output_dict[prefix+'sld'].add(sanitized_ns_name)
                    output_dict[prefix+'tld'].add(f"{'.'.join(ns_name_parts[1:])}.")
                elif len(ns_name_parts) > 0:
                    output_dict[prefix+'tld'].add(f"{ns_name_parts[0]}.")
                else:
                    logger.debug(f"Nameserver {ns_name} has no ns_name_parts")
                    logger.debug(extracted_ns)
                    logger.debug(current_name)
                    raise TypeError()
                # Add data for current_name
                if len(extracted_current.domain) > 0:
                    output_dict[prefix+'sld'].add(f"{extracted_current.domain}.{extracted_current.suffix}.")
                    output_dict[prefix+'tld'].add(f"{extracted_current.suffix}.")
                elif len(current_name_parts) > 1:
                    output_dict[prefix+'sld'].add(sanitized_current_name)
                    output_dict[prefix+'tld'].add(f"{'.'.join(current_name_parts[1:])}.")
                elif len(current_name_parts) > 1:
                    output_dict[prefix+'tld'].add(f"{current_name_parts[0]}.")
            # If ip for the hostname is provided in the additional section then use that
            if ns_name in ip_dict:
                auth_ns[ns_name] = ip_dict[ns_name].copy()
            elif output_dict is not None and sanitized_ns_name in self.active_resolutions:
                # Else if the current ns_name is currently being resolved, add current_name to non hazardous list
                output_dict['nonhazardous_domains'].add(current_name)
            elif output_dict is not None and (
                    extracted_ns.domain != extracted_current.domain or 
                    extracted_ns.suffix != extracted_current.suffix
                ):            
                # Add name to active_resolutions, this will prevent it from
                # being reresolved in a cyclic dependency, but only add if not tld
                self.active_resolutions.add(sanitized_ns_name)
                # Use saved nameserver node for secondary resolution, or add new one if doesn't exist
                if  ns_name in node_nameservers:
                    ns_node = node_nameservers[ns_name] 
                else:
                    ns_node = node_list.create_node(ns_name, Node.infer_node_type(ns_name, is_ns=True))
                    ns_node.is_public_suffix = is_public_suffix
                # Else if the current ns_name is not already being resolved and
                # the ns_name and the current_name are not part of the same domain and no 
                # output_dict is provided (ie. not parsing a tld) try resolving the hostname for its ips
                reresolved_ns = (await self.map_name(original_name=ns_name, output_dict=output_dict, 
                    prefix=prefix, is_ns=True, current_node=ns_node, node_list=node_list)).get(ns_name, None)
                if reresolved_ns is not None:
                    # If reresolution is successful then add to auth_ns
                    auth_ns[ns_name] = reresolved_ns.copy()
            if ns_name in node_nameservers and ns_name in auth_ns:
                for ip in auth_ns[ns_name]:
                    ip_node = node_list.create_node(ip, Node.infer_node_type(ip))
                    node_nameservers[ns_name].trusts(ip_node, node_trust_type)
        return auth_ns

    async def query(self, *args, **kwargs):
        response = await self.pydns.query(*args, **kwargs)
        return response

    # Recursively resolve a given hostname
    # original_name - The hostname
    # output_dict - Dictionary to store all ns, tld, sld, ip, and hazardous_domain data
    # prefix - String indicating category of resolved hostnames, particulary if 
    #          the hostname came from resolving a public suffix dependency (ex. resolving co.uk)
    # name - A truncated form of the name used as the default for handling queries
    # is_ns - A flag to indicate that function call came from resolving a prior NS record
    # current_node - Object representing current dns hostname
    async def map_name(self, original_name, output_dict, prefix="", name=None, is_ns=False, current_node=None, node_list=None):
        # If current_node and node_list are both set, add current_node to node_list
        if current_node and node_list:
            node_list.add(current_node)
        # Initialize auth_ns to store the authoritative nameservers to query in each iteration
        auth_ns = None
        # When output_dict is empty from first creation, 
        # create a set within output_dict to store hazardous domains, misconfigurations, ipv4, 
        # ipv6, ns data, and to store nonhazardous domains in cases of cyclic dependencies
        if isinstance(output_dict,dict) and len(output_dict) == 0:
            output_dict['misconfigured_domains'] = defaultdict(QuerySummaryList)
            output_dict['hazardous_domains'] = QuerySummaryList()
            output_dict['nonhazardous_domains'] = set()
            output_dict['ipv4'] = set()
            output_dict['ipv6'] = set()
            output_dict['ns'] = set()
            output_dict['tld'] = set()
            output_dict['sld'] = set()
            output_dict['ps_ns'] = set()
            output_dict['ps_ipv4'] = set()
            output_dict['ps_ipv6'] = set()
            output_dict['ps_tld'] = set()
            output_dict['ps_sld'] = set()


        # Extract and generate name_parts from name if available
        # Else extract from original_name
        if not name:
            # Convert original name to lowercase and add trailing period for uniformity
            # Save original for querying where minimized name doesnt work
            original_name =  original_name.lower()
            if original_name[-1] != ".":
                original_name = f"{original_name}."
            name = original_name     
        # Split domain and suffix by periods and remove any empty strings
        name_parts = [part for part in name.split('.') if len(part) > 0]
        extracted_name = extract(name)
        # Return cached past resolutions to prevent cyclic dependencies and reduce queries
        if name in self.past_resolutions:
            return self.past_resolutions[name]
        # If name is only tld
        isTLD = len(name_parts) <= 1
        # If extracted_name doesn't have a domain then name must be a public suffix
        if extracted_name.domain == '':
            prefix = "ps_"
        if isTLD:
            # Base case: If name is tld, then select a rootserver to use as the authoritative ns
            auth_ns = self.get_root_server()
        else:
            # Create name from every part of current name except first (ex. ns1.example.com -> example.com)
            superdomain = f"{'.'.join(name_parts[1:])}."
            superdomain_node = None
            if current_node:
                superdomain_node = node_list.create_node(name=superdomain, node_type=Node.infer_node_type(superdomain))
                current_node.trusts(superdomain_node, "provisioning")
            # These are the authoritative nameservers from the super domain
            # (ie. com => a.gtld-servers.net => google.com)
            auth_ns = await self.map_name(
                name=superdomain, 
                output_dict=output_dict, prefix=prefix, 
                original_name=original_name, 
                current_node=superdomain_node, 
                node_list=node_list
            )

        # Authoritative nameserver querying split into two parts: First query the authoritative nameservers 
        # for the superdomain to get the the authoritative nameservers for the domain, then querying process
        # repeats with the authoritative nameservers for the domain to get the final set of authoritative nameservers
        for i in range(2):
            node_trust_type = "parent" if i == 0 else "child"
            new_auth_ns = defaultdict(set)
            query_response_list = []
            # Flag to detect if atleast one nameserver did not timeout 
            has_valid_response = False
            # Flag to check if all responding nameservers have an RCODE of 3 (NXDOMAIN);
            all_nxdomain = True
            # Flag to check if all responding nameservers have an RCODE of 0 (NOERROR), but no records are returned
            empty_nonterminal = True
            # List of compiled ip, nameserver, ns_node tuples compiled from all nameservers in auth_ns
            ip_list = []
            # Query name for each ip for each ns in auth_ns
            for nameserver, ip_set in auth_ns.items():
                nameserver_node = node_list.create_node(nameserver, "nameserver")
                for ip in ip_set:
                    nameserver_ip_node = node_list.create_node(ip, Node.infer_node_type(ip))
                    nameserver_node.trusts(nameserver_ip_node, node_trust_type)
                    ip_list.append((ip, nameserver, nameserver_node))

            query_requests = []
            # Start query for each ip in ip_list concurrently
            for ip, nameserver, nameserver_node in ip_list:
                query_name = name
                query_requests.append(self.query(domain=query_name, nameserver=ip))
            query_responses = await asyncio.gather(*query_requests)
            query_response_list += query_responses
            for count, record in enumerate(ip_list):
                # Unpack ip_list record
                ip, nameserver, nameserver_node = record
                query_name = name
                query_response = query_responses[count]
                records = query_response['data'].values()
                # If records are not returned, perform additional checks to see if query timed out or 
                # returned NXDOMAIN, else set NXDOMAIN flag to false and valid reponse flag to true
                if len(records) == 0:
                    ns_timed_out = "timeout" in query_response['rcodes']
                    if not ns_timed_out:
                        has_valid_response = True
                        # Flag to check if current response is NXDOMAIN
                        nxdomain = query_response['rcodes']['NS'] == 3
                        if not nxdomain:
                            all_nxdomain = False
                            # If RCODE is 0 (NOERROR) then recycle current ip address for next set of queries
                            if query_response['rcodes']['NS'] == 0:
                                current_node.trusts(nameserver_node, node_trust_type)
                                new_auth_ns[nameserver].add(ip)
                                continue
                            else:
                                # If rcode is not noerror then can't be empty nonterminal
                                empty_nonterminal = False
                            # Since the nameserver hasn't timed out or returned NXDOMAIN, if the current name
                            # isn't the full hostname, repeat the query with the full hostname
                            if name != original_name:
                                query_name = original_name
                                query_response = await self.query(domain=query_name, nameserver=ip) 
                                query_response_list.append(query_response)
                                records = query_response['data'].values()
                                if len(records) == 0:
                                    ns_timed_out = "timeout" in query_response['rcodes']
                                    if not ns_timed_out and query_response['rcodes']['NS'] == 0:
                                        new_auth_ns[nameserver].add(ip)
                                        current_node.trusts(nameserver_node, node_trust_type)
                                        continue
                        else:
                            # If rcode is nxdomain then can't be empty nonterminal
                            empty_nonterminal = False
                else:
                    has_valid_response = True
                    all_nxdomain = False
                    empty_nonterminal = False

                # Compile returned records into dictionary of authoritative nameservers
                # and their corresponding ip addresses
                parsed_records = await self.parse(
                    query_name, 
                    records, 
                    output_dict if not isTLD else None, prefix, 
                    is_ns=is_ns, 
                    current_node=current_node, 
                    node_list=node_list,
                    node_trust_type=node_trust_type
                )
                # If one of the returned nameservers is '.' mark as invalid 
                # NS record data misconfiguration
                if '.' in parsed_records:
                    output_dict['misconfigured_domains']['invalid_ns_record'].add(
                        QuerySummary(name=name,rcodes=query_response['rcodes'], nameserver=query_response['nameserver'])
                    )
                # Add current set parsed records to dictionary of parsed records
                new_auth_ns.update(parsed_records)
            # If auth_ns is still empty => query returned no nameservers so domain is hazardous,
            # unless a cyclic dependency has occurred, in which case nameserver will be added to nonhazardous domains
            # Else if empty_nonterminal flag is still set, mark current node as empty nonterminal
            if has_valid_response and all_nxdomain and len(new_auth_ns) == 0 and name not in output_dict['nonhazardous_domains']:
                # If error on first itereation and name is not ip add name to output_dicts hazardous set
                # Else add name to misconfiguration set for missing ns records
                if i==0:
                    if name_parts[-1].isdigit():
                        current_node.is_misconfigured = True
                        current_node.misconfigurations.add("ip_ns_records")
                        for query_response in query_response_list:
                            output_dict['misconfigured_domains']['ip_ns_records'].add(
                                QuerySummary(name=name,rcodes=query_response['rcodes'], nameserver=query_response['nameserver'])
                            )
                    else:
                        current_node.is_hazardous = True;
                        for query_response in query_response_list:
                            output_dict['hazardous_domains'].add(QuerySummary(name=name,rcodes=query_response['rcodes'], nameserver=query_response['nameserver']))
                else:
                    current_node.is_misconfigured = True
                    current_node.misconfigurations.add("missing_ns_records")
                    for query_response in query_response_list:
                        output_dict['misconfigured_domains']['missing_ns_records'].add(
                            QuerySummary(name=name,rcodes=query_response['rcodes'], nameserver=query_response['nameserver'])
                        )
                if len(extracted_name.domain) > 0:
                    output_dict[prefix+'sld'].add(f"{extracted_name.domain}.{extracted_name.suffix}.")
                    output_dict[prefix+'tld'].add(f"{extracted_name.suffix}.")
                elif len(name_parts) > 1:
                    output_dict[prefix+'sld'].add(name)
                    output_dict[prefix+'tld'].add(f"{'.'.join(name_parts[1:])}.")
                else:
                    output_dict[prefix+'tld'].add(f"{name_parts[0]}.")
                # Break iteration since is new_auth_ns is empty, no further resolutions can be made
                break
            elif empty_nonterminal:
                current_node.is_empty_nonterminal = True
            auth_ns = new_auth_ns
        # Remove name from active_resolutions to end the hold on it being reresolved
        self.active_resolutions.discard(name)
        # Add to past_resolutions so that reresolutions hit the cache rather than triggering another cyclic dependency
        self.past_resolutions[name] = new_auth_ns
        return new_auth_ns

    # Return a dictionary containing all the ns, tld, sld, ip, and hazardous domains for a given hostname,
    # filters the output from map_name
    # name - The hostname to search for
    # is_ns - Flag to treat the hostname as a nameserver (used for A record handling and node type determinations)
    # db_json - Flag to return nodelist json along with domain_dict
    # db_json - Flag to return nodelist rdf along with domain_dict
    # version - Value for versioning facet on uid predicates for nodelist, defaults to timestamp at start of crawl
    async def get_domain_dict(self, name, is_ns=False, db_json=False, db_rdf=False, version=None): 
        self.nameservers = defaultdict(set, self.root_servers)
        # Default version to timestamp at start of crawl
        if not version:
            version = self.get_timestamp()
        node_list = NodeList(version=version)
        # Initialize the dictionary to store the raw zone data
        output_dict = defaultdict(set)
        node = node_list.create_node(name=name, node_type=Node.infer_node_type(name, is_ns))
        auth_ns = await self.map_name(name, output_dict, is_ns=is_ns, current_node=node, node_list=node_list)
        # Initialize the dictionary to store the formatted zone data
        domain_dict = {"query":name}
        # Convert values in hazard, ns, ip, and tld/sld sets to uppercase to remove any case duplicates
        # Add ip, ns and hazardous domain data to domain_dict, casting to list to make the data JSON serializable.
        domain_dict['misconfigured_domains'] = {}
        for k,v in output_dict['misconfigured_domains'].items():
            domain_dict['misconfigured_domains'][k] = v.queries
        domain_dict['hazardous_domains'] = output_dict['hazardous_domains'].queries
        domain_dict['ns'] = list({val.lower() for val in output_dict['ns']})
        domain_dict['ipv4'] = list({val.lower() for val in output_dict['ipv4']})
        domain_dict['ipv6'] = list({val.lower() for val in output_dict['ipv6']})
        domain_dict['tld'] = list({val.lower() for val in output_dict['tld']})
        domain_dict['sld'] = list({val.lower() for val in output_dict['sld']})
        domain_dict['ps_ns'] = list({val.lower() for val in output_dict['ps_ns']})
        domain_dict['ps_ipv4'] = list({val.lower() for val in output_dict['ps_ipv4']})
        domain_dict['ps_ipv6'] = list({val.lower() for val in output_dict['ps_ipv6']})
        domain_dict['ps_tld'] = list({val.lower() for val in output_dict['ps_tld']})
        domain_dict['ps_sld'] = list({val.lower() for val in output_dict['ps_sld']})

        if db_json or db_rdf:
            response = {'domain_dict':domain_dict}
            if db_json:
                response['json'] = node_list.json()
            if db_rdf:
                response['rdf'] = node_list.rdf()
            return response
        return domain_dict

# if __name__ == "__main__":
#     resolver = DNSResolver()
#     zone_data = resolver.get_domain_dict("google.com")
        

