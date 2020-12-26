from collections import OrderedDict

class LRUCache:
    def __init__(self, capacity=128):
        self.capacity = capacity;
        self.cache = OrderedDict() if self.capacity is not None else {}

    def has(self, key):
        return key in self.cache

    def get(self, key):
        if not self.has(key):
            return None
        # If limited capacity move most recently accessed key to beginning
        if self.capacity is not None:
            self.cache.move_to_end(key)
        return self.cache[key]
            

    def set(self, key, value):
        if self.is_full():
            self.pop()
        self.cache[key] = value
        self.cache.move_to_end(key)
        return (key, value)

    def size(self):
        return len(self.cache)

    def is_full(self):
        return self.size() == self.capacity

    def pop(self):
        return self.cache.popitem(last=False)