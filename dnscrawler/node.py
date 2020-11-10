from datetime import datetime, timezone
from ipaddress import ip_address

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
    "tld":"TLD"
}

# Get RFC 3339 timestamp
def get_timestamp():
    timestamp = datetime.now(timezone.utc).astimezone()
    return timestamp.isoformat()

class Node:
    def __init__(self, name, node_type='nameserver'):
        self.type = node_type
        name = name.lower()
        # Make all hostnames uniform
        if self.type not in ('ipv4', 'ipv6') and name[-1] != '.':
            name += '.'
        self.name = name
        self.is_hazardous = False
        self.is_misconfigured = False
        self.misconfigurations = []
        self.trusts = NodeList()

    # Generate external id for node
    def xid(self):
        return f"{node_type_prefix[self.type]}${self.name}"

    # Generate internal uid replacement for node
    def uid(self):
        return f"_:{self.xid()}"

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
                return "domain"


    # Node type getter and setter 
    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if not value in node_type_prefix:
            raise ValueError(f"Node type {value} is not valid")
        self._type = value
    
    # Generate json serializable dictionary for node
    def json(self):
        data = {
            'name':self.name,
            'dgraph.type':self.type,
            'uid':self.uid(),
            'xid':self.xid(),
            'is_hazardous':self.is_hazardous,
            'is_misconfigured':self.is_misconfigured,
            'misconfigurations':self.misconfigurations,
            'last_seen':get_timestamp(),
            'trusts': [node.json() for node in self.trusts.nodes.values()]
        }
        return data
