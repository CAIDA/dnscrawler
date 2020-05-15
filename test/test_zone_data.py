from io import StringIO 
from unittest import TestCase 
from unittest.mock import patch
import sys
sys.path.append("../")
from dnscrawler import print_zone_data,print_zone_json
from dnscrawler.logger import log

class TestZoneData(TestCase):
    def test_print_zone_data(self):
        with patch('sys.stdout', new=StringIO()) as output:
            print_zone_data("google.com")
        print(output.getvalue())
    def test_print_zone_json(self):
        with patch('sys.stdout', new=StringIO()) as output:
            print_zone_json("google.com")
        print(output.getvalue())

if __name__ == "__main__":
    unittest.main()