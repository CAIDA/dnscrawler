from io import StringIO 
import sys
sys.path.append("../")
from dnscrawler import print_zone_data,print_zone_json,get_domain_dict
from dnscrawler.logger import log

if __name__ == "__main__":
    log(get_domain_dict("amazon.com"))