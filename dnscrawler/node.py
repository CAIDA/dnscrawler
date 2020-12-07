from datetime import datetime, timezone
from ipaddress import ip_address
from collections import defaultdict
from tldextract import extract
from traceback import print_stack
if __name__ == "node":
    from nodelist import NodeList
else:
    from .nodelist import NodeList

# Lookup table for DNS node types and corresponding prefixes
node_type_prefix = {
    'nameserver':"NSR",
    'ipv4':"IP4",
    'ipv6':"IP6",
    "domain":"DMN",
    "subdomain":"SDN",
    "tld":"TLD",
    "public_suffix_tld":"PS_TLD",
    # "public_suffix_nameserver":"PS_NS",
    # "public_suffix_ipv4":"PS_IP4",
    # "public_suffix_ipv6":"PS_IP6",
    # "public_suffix_domain":"PS_DMN",
    # "public_suffix_subdomain":"PS_SDN",
}

# Get RFC 3339 timestamp
def get_timestamp():
    timestamp = datetime.now(timezone.utc).astimezone()
    return timestamp.isoformat()

class Node:
    def __init__(self, name, node_type='nameserver', root_nodelist=None):
        self.type = node_type
        self.is_hazardous = False
        self.is_misconfigured = False
        self.is_empty_nonterminal = False
        self.is_public_suffix = False
        self.misconfigurations = set()
        self._trusts = defaultdict(NodeList)
        name = name.lower()
        if "ip" not in self.type:
            # Add trailing period to all hostnames
            if name[-1] != '.':
                name = f"{name}."

            # Add parent domain bidirectional relationship
            # If node is a subdomain then parent is the public suffix domain
            # Elif node is a public suffix domain then the parent is public suffix
            # Else parent is public suffix so parent is superdomain
            extracted_name = extract(name)
            if extracted_name.subdomain != "":
                parent_name = f"{extracted_name.domain}.{extracted_name.suffix}."
            elif extracted_name.domain != "":
                parent_name = f"{extracted_name.suffix}."
            else:
                name_parts = [part for part in name.split('.') if len(part) > 0]
                # If node has more than one label then parent is superdomain
                # Else node is tld, and has no bidirectional parent
                if len(name_parts) > 1:
                    parent_name = f"{'.'.join(name_parts[1:])}."
                else:
                    parent_name = name
            parent_type = self.infer_node_type(parent_name)
            # If parent name is not name (node is not the parent domain), add bidirectional trust
            if name != parent_name:
                if root_nodelist:
                    parent_node = root_nodelist.create_node(parent_name, parent_type)
                else:
                    parent_node = Node(parent_name, parent_type)
                self.trusts(parent_node, "provisioning")
        self.name = name

    # Generate external id for node
    def xid(self):
        return f"{node_type_prefix[self.type]}${self.name}"

    # Generate internal uid replacement for node
    def uid(self):
        return f"_:{self.xid()}"

    def __repr__(self):
        return self.xid()

    # Function to guess node type if unknown
    @staticmethod
    def infer_node_type(name, is_ns=False):
        name_parts = [part for part in name.split('.') if len(part) > 0]
        if is_ns:
            return "nameserver"
        # Differentiate between a tld and ipv6 through the presence of a ':' 
        elif len(name_parts) == 1 and ":" not in name_parts[0]:
            return "tld"
        else:
            try:
                ip = ip_address(name)
                return f"ipv{ip.version}"
            except:
                extracted_name = extract(name)
                if extracted_name.domain == '':
                    return "public_suffix_tld"
                elif extracted_name.subdomain == '':
                    return "domain"
                else:
                    return "subdomain"


    # Node type getter and setter 
    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if not value in node_type_prefix:
            raise ValueError(f"Node type {value} is not valid")
        self._type = value

    # Function to add trust dependencies
    def trusts(self, node, trust_type="parent"):
        return self._trusts[trust_type].add(node)

    # Generate json serializable dictionary for node
    def json(self, full_data=True):
        if not full_data:
            return {
                'uid':self.uid()
            }
        data = {
            'name':self.name,
            'dgraph.type':self.type,
            'uid':self.uid(),
            'xid':self.xid(),
            'is_hazardous':self.is_hazardous,
            'is_misconfigured':self.is_misconfigured,
            'is_empty_nonterminal':self.is_empty_nonterminal,
            'is_public_suffix':self.is_public_suffix,
            'misconfigurations':list(self.misconfigurations),
            'last_seen':get_timestamp(),
        }
        for key, nodelist in self._trusts.items():
            data[key+"_trusts"] = nodelist.json(full_data=False)
        filtered_data = {k:v for k,v in data.items() if v is not False}
        return data
