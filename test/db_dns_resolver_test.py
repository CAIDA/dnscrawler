import sys
sys.path.append("../")
from dnscrawler import DNSResolver, load_schema, DatabaseConnection
from dnscrawler.logger import log
import json
import asyncio

async def main():
    with DatabaseConnection("localhost:9080") as db, load_schema() as schema_file:
        schema = schema_file.read()
        # TESTING
        db.drop_all()
        db.set_schema(schema)
        # resolver = DNSResolver([{'addr':"192.172.226.186",'port':1080}])
        resolver = DNSResolver(ipv4_only=True)
        # resolver = DNSResolver()
        data = await resolver.get_domain_dict("google.com", db_json=True)
        # Empty non-terminal
        # data = await resolver.get_domain_dict("caag.state.ca.us", db_json=True)
        # Hazardous domain
        # data = await resolver.get_domain_dict("PREGNANCYCALCULATE.COM.", db_json=True)
        # Cross zone loops
        # data = await resolver.get_domain_dict("amazon.com", db_json=True)
        # Early ns records
        # data = await resolver.get_domain_dict("aridns.net.au", db_json=True)
        # Retry domain records due to timeout
        # data = await resolver.get_domain_dict("AMERICUSGA.GOV", db_json=True)
        domain_dict = data['domain_dict']
        nodelist_json = data['json']
        print(json.dumps(domain_dict))
        db.create(nodelist_json)

if __name__ == "__main__":
    asyncio.run(main())