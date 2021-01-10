from collections import defaultdict
from objsize import get_deep_size

class NSSet(dict):
    '''A hashable ordered collection of nameservers
    
    Args:
        initial (optional): Defaults to None. If set to NSSet or similar,
            will fill self with nameservers and ips from initial.

    Attributes:
        nameservers (dict): Maps nameservers to sets of ips
    '''

    __slots__ = ['nameservers']

    def __init__(self, initial:'NSSet' = None):
        if initial:
            self.update(initial)

    # TODO: Format both nameservers and ips added to NSSet

    def __missing__(self, key: str) -> set:
        '''Creates a set for the given key in nameservers if one doesn't 
        exist already
        
        Args:
            key: The key to add to nameservers

        Returns:
            The set of ips associate with key
        '''
        self[key] = set()
        return self[key]

    def __delitem__(self, key:str) -> set:
        '''Remove a key from nameservers
        
        Args:
            key: The nameserver to set ips for
            value: The set of ips to assign

        Returns:
            The set of ips associate with key, or None if doesn't exist
        '''
        return self.pop(key, None)

    def __repr__(self) -> str:
        '''Returns string representation of NSSet'''
        ns_data = []
        # Create list of tuples of nameservers and correspond ips, 
        # sorted by nameserver
        nameservers = sorted(self.items(), key=lambda x:x[0])
        for nameserver, ips in nameservers:
            sorted_ips = sorted(list(ips))
            ip_str = ', '.join(sorted_ips)
            ns_ip_str = f"{nameserver}: {ip_str}"
            ns_data.append(ns_ip_str)
        ns_set_str = 'NSSet'
        if len(ns_data) > 0:
            ns_data_str = '\n'.join(ns_data) 
        else:
            ns_data_str = '(empty)'
        ns_set_str = f'{ns_set_str}\n{ns_data_str}'
        return ns_set_str

    def __hash__(self) -> int:
        '''Return a hash of the string representation of the NSSet'''
        return hash(str(self))

    def update(self, other:'NSSet'):
        '''Merge two NSSets

        Args:
            other: NSSet or similar to merge with self
        '''
        for nameserver, ips in other.items():
            self[nameserver].update(ips)

    def copy(self) -> 'NSSet':
        '''Create a deep copy of the NSSet
            
        Returns:
            Copy of NSSet
        '''
        new_nsset = NSSet()
        new_nsset.update(self)
        return new_nsset