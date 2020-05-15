from app import zone_data
from logger import log
import sys

if(len(sys.argv) != 2):
    print("Usage: python dnscrawler <domain>")
else:
    log(zone_data(sys.argv[1]))