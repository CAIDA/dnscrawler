from collections import OrderedDict

from objsize import get_deep_size

class LRUCache:
    def __init__(self, capacity=128):
        self.capacity = capacity
        self.cache = OrderedDict() if self.capacity is not None else {}
        self.cache_info = {"hits": 0, "misses": 0, "capacity": self.capacity}

    def has(self, key):
        return key in self.cache

    def get(self, key):
        if not self.has(key):
            self.cache_info['misses'] += 1
            return None
        self.cache_info['hits'] += 1
        # If limited capacity move most recently accessed key to beginning
        if self.capacity is not None:
            self.cache.move_to_end(key)
        return self.cache[key]

    def set(self, key, value):
        if self.is_full():
            self.pop()
        self.cache[key] = value
        if self.capacity:
            self.cache.move_to_end(key)
        return (key, value)

    def size(self):
        return len(self.cache)

    def is_full(self):
        return self.size() == self.capacity

    def pop(self):
        return self.cache.popitem(last=False)

    def stats(self):
        current_cache_info = self.cache_info.copy()
        current_cache_info['size'] = self.size()
        current_cache_info['memory'] = get_deep_size(self.cache)
        return current_cache_info
