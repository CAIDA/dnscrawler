from collections import defaultdict
from functools import lru_cache
from random import choice
from tldextract import extract
import os


if __name__ == "__main__":
    import constants
    from logger import log
    from pydns import PyDNS
    from querysummary import QuerySummary
    from querysummarylist import QuerySummaryList
    from db import DatabaseConnection
    from node import Node
    from nodelist import NodeList
else:
    from . import constants
    from .logger import log
    from .pydns import PyDNS
    from .querysummary import QuerySummary
    from .querysummarylist import QuerySummaryList
    from .db import DatabaseConnection
    from .node import Node
    from .nodelist import NodeList

class DNSResolver:
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
            "b.root-servers.net.":{"199.9.14.201"},
            "c.root-servers.net.":{"192.33.4.12"},
            "d.root-servers.net.":{"199.7.91.13"},
            "e.root-servers.net.":{"192.203.230.10"},
            "f.root-servers.net.":{"192.5.5.241"},
            "g.root-servers.net.":{"192.112.36.4"},
            "h.root-servers.net.":{"198.97.190.53"},
            "i.root-servers.net.":{"192.36.148.17"},
            "j.root-servers.net.":{"192.58.128.30"},
            "k.root-servers.net.":{"193.0.14.129"},
            "l.root-servers.net.":{"199.7.83.42"},
            "m.root-servers.net.":{"202.12.27.33"},
        };
        self.xid_cache = {}
        self.nameservers = defaultdict(set, self.root_servers)

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
    def parse(self, current_name, records, output_dict=None, prefix="", is_ns=False, current_node=None, node_list=None):
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
        for record in records:
            # Add all nameservers for names that are a substring of current_name to ns_set
            if record['type'] == 'NS' and record['name'].lower() in current_name:
                if record['name'].lower() == current_name:
                    node_nameservers[record['data']] = Node(record['data'], Node.infer_node_type(record['data'], is_ns=True))
                    if current_node:
                        current_node.trusts.add(node_nameservers[record['data']])
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
                        if current_node:
                            current_node.trusts.add(Node(record['data'], Node.infer_node_type(record['data'])))
                        output_dict[record['name'].lower()].add(record['data'].lower())
                        # If is_ns is true, query came from resolving a previous NS record, so the corresponding
                        # a record can be treated as a nameserver
                        if is_ns:
                            ns_set.add(current_name)
        # Compile sets of all ips for authoritative ns into auth_ns
        for ns_name in ns_set:
            # Seperate ns_name and current_name by domain and suffix in order to avoid
            # reresolution if both the ns and the current_name belong to the same domain
            # (ie. don't reresolve ns1.example.com if current name is example.com)
            extracted_ns = extract(ns_name)
            extracted_current = extract(current_name)
            # Get sanitized name (domain + suffix) for checking if in active_resolutions
            ns_name_parts = [part for part in extracted_ns.domain.split('.')+extracted_ns.suffix.split('.') if len(part) > 0]
            current_name_parts = [part for part in extracted_current.domain.split('.')+extracted_current.suffix.split('.') if len(part) > 0]
            sanitized_ns_name = f"{'.'.join(ns_name_parts)}."
            sanitized_current_name = f"{'.'.join(current_name_parts)}."
            # Add TLD and SLD data to output_dict
            if output_dict is not None:
                # Add data for each ns
                if len(extracted_ns.domain) > 0:
                    output_dict[prefix+'sld'].add(f"{extracted_ns.domain}.{extracted_ns.suffix}.")
                    output_dict[prefix+'tld'].add(f"{extracted_ns.suffix}.")
                elif len(ns_name_parts) > 1:
                    output_dict[prefix+'sld'].add(sanitized_ns_name)
                    output_dict[prefix+'tld'].add(f"{'.'.join(ns_name_parts[1:])}.")
                else:
                    output_dict[prefix+'tld'].add(f"{ns_name_parts[0]}.")

                # Add data for current_name
                if len(extracted_current.domain) > 0:
                    output_dict[prefix+'sld'].add(f"{extracted_current.domain}.{extracted_current.suffix}.")
                    output_dict[prefix+'tld'].add(f"{extracted_current.suffix}.")
                elif len(current_name_parts) > 1:
                    output_dict[prefix+'sld'].add(sanitized_current_name)
                    output_dict[prefix+'tld'].add(f"{'.'.join(current_name_parts[1:])}.")
                else:
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
                ns_node = node_nameservers[ns_name] if  ns_name in node_nameservers else node_list.add(Node(ns_name, Node.infer_node_type(ns_name, is_ns=True)))
                # Else if the current ns_name is not already being resolved and
                # the ns_name and the current_name are not part of the same domain and no 
                # output_dict is provided (ie. not parsing a tld) try resolving the hostname for its ips
                reresolved_ns = self.map_name(original_name=ns_name, output_dict=output_dict, 
                    prefix=prefix, is_ns=True, current_node=ns_node, node_list=node_list).get(ns_name, None)
                if reresolved_ns is not None:
                    # If reresolution is successful then add to auth_ns
                    auth_ns[ns_name] = reresolved_ns.copy()
            if ns_name in node_nameservers and ns_name in auth_ns:
                for ip in auth_ns[ns_name]:
                    node_nameservers[ns_name].trusts.add(Node(ip, Node.infer_node_type(ip)))
        return auth_ns

    # Recursively resolve a given hostname
    # original_name - The hostname
    # output_dict - Dictionary to store all ns, tld, sld, ip, and hazardous_domain data
    # prefix - String indicating category of resolved hostnames, particulary if 
    #          the hostname came from resolving a public suffix dependency (ex. resolving co.uk)
    # name - A truncated form of the name used as the default for handling queries
    # is_ns - A flag to indicate that function call came from resolving a prior NS record
    # current_node - Object representing current dns hostname
    def map_name(self, original_name, output_dict, prefix="", name=None, is_ns=False, current_node=None, node_list=None):
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
        isTLD = len(name_parts) == 1
        # If extracted_name doesn't have a domain then name must be a suffix
        isSuffix = extracted_name.domain == ''
        if isTLD:
            # Base case: If name is tld, then select a rootserver to use as the authoritative ns
            auth_ns = self.get_root_server()
        else:
            # Create name from every part of current name except first (ex. ns1.example.com -> example.com)
            superdomain = f"{'.'.join(name_parts[1:])}."
            superdomain_node = current_node.trusts.add(Node(name=superdomain, node_type=Node.infer_node_type(superdomain))) if current_node else None
            # These are the authoritative nameservers from the super domain
            # (ie. com => a.gtld-servers.net => google.com)
            if isSuffix:
                prefix = "ps_"
            auth_ns = self.map_name(name=superdomain, output_dict=output_dict, prefix=prefix, original_name=original_name, current_node=superdomain_node, node_list=node_list);

        # Authoritative nameserver querying split into two parts: First query the authoritative nameservers 
        # for the superdomain to get the the authoritative nameservers for the domain, then querying process
        # repeats with the authoritative nameservers for the domain to get the final set of authoritative nameservers
        for i in range(2):
            new_auth_ns = defaultdict(set)
            query_response_list = []
            # Query name for each ip for each ns in auth_ns
            for nameserver, ip_set in auth_ns.items():
                nameserver_node = Node(nameserver, "nameserver")
                for ip in ip_set:
                    nameserver_ip_node = Node(ip, Node.infer_node_type(ip))
                    nameserver_node.trusts.add(nameserver_ip_node)
                    query_name = name
                    print(f"Querying {nameserver} for {query_name} ({ip})")
                    query_response = self.pydns.query(domain=query_name, nameserver=ip)
                    query_response_list.append(query_response)
                    records = query_response['data'].values()
                    if len(records) == 0:
                        ns_timed_out = "timeout" in query_response['rcodes']
                        # Create flag to check if RCODE is 3 (NXDOMAIN); if it is, do not repeat query with original name
                        nxdomain = not ns_timed_out and query_response['rcodes'][2] == 3
                        if not nxdomain and name != original_name:
                            query_name = original_name
                            query_response = self.pydns.query(domain=query_name, nameserver=ip)
                        records = query_response['data'].values()
                        ns_timed_out = "timeout" in query_response['rcodes']
                        nxdomain = not ns_timed_out and query_response['rcodes'][2] == 3
                        # As long as query response still is not (NXDOMAIN), reuse previous zone cut's 
                        # nameservers for next set of queries
                        if len(records) == 0 and not nxdomain and not ns_timed_out:
                            new_auth_ns[nameserver].add(ip)
                            continue
                    else:
                        nxdomain = False
                    # If isTLD do not provide output_dict for parse as tlds do not need to be recursed
                    new_auth_ns.update(self.parse(query_name, records, output_dict if not isTLD else None, prefix, is_ns=is_ns, current_node=current_node, node_list=node_list))
            # If auth_ns is still empty => query returned no nameservers so domain is hazardous,
            # unless a cyclic dependency has occurred, in which case nameserver will be added to nonhazardous domains
            if len(new_auth_ns) == 0 and name not in output_dict['nonhazardous_domains']:
                # If error on first itereation and name is not ip add name to output_dicts hazardous set
                # Else add name to misconfiguration set for missing ns records
                if i==0:
                    if name_parts[-1].isdigit():
                        for query_response in query_response_list:
                            output_dict['misconfigured_domains']['ip_ns_records'].add(
                                QuerySummary(name=name,rcodes=query_response['rcodes'], nameserver=query_response['nameserver'])
                            )
                    else:
                        current_node.is_hazardous = True;
                        for query_response in query_response_list:
                            output_dict['hazardous_domains'].add(QuerySummary(name=name,rcodes=query_response['rcodes'], nameserver=query_response['nameserver']))
                else:
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
            auth_ns = new_auth_ns
        # Remove name from active_resolutions to end the hold on it being reresolved
        self.active_resolutions.discard(name)
        # Add to past_resolutions so that reresolutions hit the cache rather than triggering another cyclic dependency
        self.past_resolutions[name] = new_auth_ns
        return new_auth_ns

    # Return a dictionary containing all the ns, tld, sld, ip, and hazardous domains for a given hostname,
    # filters the output from map_name
    # name - The hostname to search for
    def get_domain_dict(self, name, is_ns=False): 
        self.nameservers = defaultdict(set, self.root_servers)
        # Initialize the dictionary to store the raw zone data
        output_dict = defaultdict(set)
        path = os.path.dirname(os.path.realpath(__file__))
        with DatabaseConnection("localhost:9080") as db, open(f"{path}/schema.txt", "r") as schema_file:
            schema = schema_file.read()
            # TESTING
            db.drop_all()
            db.set_schema(schema)
            node_list = NodeList()
            node = node_list.add(Node(name=name, node_type=Node.infer_node_type(name, is_ns)))
            auth_ns = self.map_name(name, output_dict, is_ns=is_ns, current_node=node, node_list=node_list)
            print(auth_ns)
            print()
            print(output_dict)
            db.create(node_list.json())
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
        return domain_dict

# if __name__ == "__main__":
#     resolver = DNSResolver()
#     zone_data = resolver.get_domain_dict("google.com")
        

