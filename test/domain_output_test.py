from io import StringIO 
import sys
sys.path.append("../")
from dnscrawler import print_zone_data,print_zone_json
from dnscrawler.logger import log

if __name__ == "__main__":
    print_zone_data("camnet.cm")