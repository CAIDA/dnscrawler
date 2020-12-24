import sys
sys.path.append("../")
from dnscrawler import DNSResolver, load_schema, DatabaseConnection
from dnscrawler.logger import log
import json
import asyncio
import time

async def main():
    with DatabaseConnection("localhost:9080") as db, load_schema() as schema_file:
        schema = schema_file.read()
        # TESTING
        db.drop_all()
        db.set_schema(schema)
        # resolver = DNSResolver([{'addr':"192.172.226.186",'port':1080}])
        resolver = DNSResolver(ipv4_only=True)
        # resolver = DNSResolver()
        print("running")
        start_time = time.time()    
        data = await resolver.get_domain_dict("google.com", db_rdf=True, version=resolver.get_timestamp())
        # Empty non-terminal
        # data = await resolver.get_domain_dict("caag.state.ca.us", db_json=True)
        # Hazardous domain
        # data = await resolver.get_domain_dict("PREGNANCYCALCULATE.COM.", db_json=True)
        # Cross zone loops
        # data = await resolver.get_domain_dict("amazon.com", db_json=True)
        # Early ns records
        # data = await resolver.get_domain_dict("aridns.net.au", db_json=True)
        # Retry domain records due to long duration
        # data = await resolver.get_domain_dict("AMERICUSGA.GOV", db_json=True)
        # Large timeout cause no output
        # data = await resolver.get_domain_dict("AMARILLO.GOV", db_json=True)
        finish_time = time.time()
        duration = finish_time - start_time
        domain_dict = data['domain_dict']
        nodelist_rdf = data['rdf']
        print(nodelist_rdf)
        db.create_rdf(nodelist_rdf)
        # nodelist_json = data['json']
        # print(json.dumps(nodelist_json))
        print(f"Duration: {duration}")

if __name__ == "__main__":
    asyncio.run(main())
