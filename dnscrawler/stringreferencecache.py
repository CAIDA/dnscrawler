from dnscrawler.lrucache import LRUCache

class StringReferenceRecord:
    '''StringReferenceRecord tracks a value and the number of references
    to that value in the StringReferenceCache
    
    Args:
        value: A canonical value stored in the StringReferenceCache.
        references (optional): Defaults to zero. Number of references to 
            value.

    Attributes:
        value (object): A canonical value stored in the 
            StringReferenceCache.
        references (int): Number of references to value.
    '''

    __slots__ = ['references', 'value']

    def __init__(self, value:object, references:int = 0):
        self.value = value
        self.references = references

    def increment_references(self) -> int:
        '''Track an increase in the number of references to value.

        Returns:
            Number of references to value.
        '''
        self.references += 1
        return self.references

    def decrement_references(self) -> int:
        '''Track an decrease in the number of references to value.

        Returns:
            Number of references to value.
        '''
        self.references -= 1
        return self.references

    def not_referenced(self) -> bool:
        '''Returns True if number of references is zero.'''
        return self.references <= 0

    def __repr__(self) -> str:
        '''Convert StringReferenceRecord to string'''
        return f"(references={self.references}, value={self.value})"

class StringReferenceCache(LRUCache):
    '''A StringReferenceCache is an LRUCache that assumes that any two
    objects with the same __str__ can be substituted for one another
    
    Attributes:
        str_to_reference (dict): Contains a mapping betweens strings
            and their canonical object representation within the cache
    '''
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.str_to_reference = {}

    def set(self, key:str, value:object) -> tuple:
        '''Add item to StringReferenceCache

        Args:
            key: String under which to store cached value
            value: Object to store in cache. Mapping between 
                value.__str__ and value will also be stored

        Returns:
            Tuple containing key and canonical value
        '''
        value_str = str(value)
        # If an object with the same __str__ as value is already in the
        # cache, assign that object to key instead
        if value_str  not in self.str_to_reference:
            # Track both the value and the number of references to the
            # value
            record = StringReferenceRecord(value)
            self.str_to_reference[value_str] = record
        else:
            record = self.str_to_reference[value_str]
        # Increment the number of references to the value
        record.increment_references()
        return super().set(key,record.value)

    def pop(self) -> tuple:
        '''Remove item from StringReferenceCache 
        
        Returns:
            Tuple containing key and value removed from cache. Removing
            value from cache will only remove it from str_to_reference
            if there are no other keys in the cache that point to that
            value.
        '''

        key, value = super().pop()
        value_str = str(value)
        record = self.str_to_reference[value_str]
        # Decrement the number of references for the value
        record.decrement_references()
        if record.not_referenced():
            del self.str_to_reference[value_str]
        return (key, value)
        
