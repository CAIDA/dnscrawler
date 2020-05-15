import unittest
import sys
sys.path.append("../")
from dnscrawler import dig
from dnscrawler import logger

class TestCache(unittest.TestCase):
    def test_query_root_cache(self):
        # Pre cache
        dig.query_root("com",("NS","A"))
        info = dig.query_root.cache_info()
        self.assertEqual(info.hits,0)
        self.assertEqual(info.currsize,1)
        # Post cache
        dig.query_root("com",("NS","A"))
        info = dig.query_root.cache_info()
        self.assertEqual(info.hits,1)
        self.assertEqual(info.currsize,1)

if __name__ == "__main__":
    unittest.main()
