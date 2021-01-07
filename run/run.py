import multiprocessing as mp
from concurrent.futures import TimeoutError
from pebble import ProcessPool
import json
import sys
import os
sys.path.append("../")
from dnscrawler import DNSResolver, load_schema, DatabaseConnection
from dnscrawler.logger import log
from glob import glob
import gzip
import time
import asyncio
import logging

logging.basicConfig(handlers=[
        logging.FileHandler("dnscrawler.log"),
        logging.StreamHandler()
    ], level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s:%(message)s')

logger = logging.getLogger(__name__)

version = DNSResolver.get_timestamp()
domain_dict_dirname = "domain_dict"
nodelist_dirname = "nodelist"
max_concurrent_crawls = 16000 

# Crawl nameserver if it hasn't already been crawled
# and output result to json file
async def create_nameserver_file(resolver, nameserver,target_dir, filetype):
    logger.info(f"Starting: {nameserver}")
    filename = nameserver
    # Create paths and directories for precompiled domain_dicts and nodelist json
    domain_dict_dirpath = f"{target_dir}/{domain_dict_dirname}"
    nodelist_dirpath = f"{target_dir}/{nodelist_dirname}"
    required_paths = [target_dir, domain_dict_dirpath, nodelist_dirpath]
    for dirpath in required_paths:
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)
    # Create paths for domain_dict and nodelist json files
    domain_dict_filepath = f"{target_dir}/{domain_dict_dirname}/{filename}.json"
    nodelist_filepath = f"{target_dir}/{nodelist_dirname}/{filename}.{filetype}"
    if not os.path.exists(domain_dict_filepath):
        crawl_kwargs = {"name":nameserver, "is_ns":True, f"db_{filetype}":True, "version":version}
        data = await resolver.get_domain_dict(**crawl_kwargs)
        domain_dict = data['domain_dict']
        if filetype == "json":
            nodelist_output = json.dumps(data[filetype])
        elif filetype == "rdf":
            nodelist_output = data[filetype]
        with open(domain_dict_filepath,"w") as domain_dict_file, open(nodelist_filepath,"w") as nodelist_output_file:
            domain_dict_file.write(json.dumps(domain_dict))
            nodelist_output_file.write(nodelist_output)
    else:
        logger.info(f"File found: {nameserver}")
    logger.info(f"Finished: {nameserver}")

async def start_crawl(coro, crawl_limiter):
    if crawl_limiter.locked():
        logger.info("Concurrent crawl limit hit")
    async with crawl_limiter:
        await coro

# Crawl all nameservers from a list in a source file
# and compile their result json into a target file
async def compile_nameserver_data(source_file,target_dir, target_file, db_target_file):
    start_time = time.time()
    logger.info(f"Start Time: {start_time}")
    target_schema_filepath = target_dir + "/schema.txt"
    # Copy schema to target directory
    with load_schema() as schema_infile, open(target_schema_filepath, "w") as schema_outfile:
        schema = schema_infile.read()
        schema_outfile.write(schema)
    # Get db_target_file extension to determine overall output
    db_target_extension = os.path.splitext(db_target_file[:-3])[1][1:]
    if db_target_extension not in ("rdf","json"):
        raise ValueError(f"Invalid db_target_file extension: {db_target_extension}")
    # Read all hostnames from source_file
    logger.info("Reading hostname list...")
    with open(source_file,"r") as nsfile:
        nameservers = nsfile.read().splitlines()
    logger.info("Starting initial crawling...")
    crawl_list = []
    concurrent_crawl_limiter = asyncio.Semaphore(max_concurrent_crawls)
    async with DNSResolver() as resolver:
        for nameserver in nameservers:
            crawl_coro = create_nameserver_file(resolver, nameserver, target_dir, db_target_extension)
            crawl_list.append(start_crawl(crawl_coro, concurrent_crawl_limiter))
        await asyncio.gather(*crawl_list)
    finish_crawl_time = time.time()
    crawl_duration = finish_crawl_time - start_time
    # Duplicate list of hostnames, remove each hostname as the its file is compiled
    missing_namservers = nameservers.copy()
    logger.info("Compiling domain_dict into jsonl file")
    with open(f"{target_dir}/{target_file}","wb") as outfile:
        for file_count, filepath in enumerate(glob(f"{target_dir}/{domain_dict_dirname}/*.json")):
            # Verify all hostnames have been crawled
            filename = os.path.basename(filepath)
            file_nameserver = os.path.splitext(filename)[0]
            missing_namservers.remove(file_nameserver)
            with open(filepath, "rb") as infile:
                logger.info(f"Compiling file: {file_count + 1}. {filepath}")
                outfile.write(infile.read())
                outfile.write('\n'.encode('utf-8'))
                infile.close()
    logger.info(f"Compiling nodelist_output into gzipped {db_target_extension} file")
    with gzip.open(f"{target_dir}/{db_target_file}","wb") as outfile:
        # If outputting json file print opening brackets
        if db_target_extension == "json":
            outfile.write("[\n".encode('utf-8'))
        for file_count, filepath in enumerate(sorted(glob(f"{target_dir}/{nodelist_dirname}/*.{db_target_extension}"))):
            with open(filepath, "rb") as infile:
                logger.info(f"Compiling file: {file_count + 1}. {filepath}")
                if file_count > 1:
                    # Add comma and newline between JSON objects, otherwise just newline
                    line_separator = ',\n' if db_target_extension == "json" else '\n'
                    outfile.write(line_separator.encode('utf-8'))
                data = infile.read().strip()
                truncated_data = data
                # If outputting JSON files, remove first and last characters 
                # from infile (opening and closing brackets) since each original 
                # JSON file contains an array with the collection of nodes
                if db_target_extension == "json":
                    truncated_data = truncated_data[1:-1]
                outfile.write(truncated_data)
                infile.close()
        # If outputting json file print closing brackets
        if db_target_extension == "json":
            outfile.write("\n]".encode('utf-8'))
        # Append newline to end of file
        outfile.write("\n".encode('utf-8'))
    # Print missing hostnames, if any
    if len(missing_namservers) > 0:
        logger.warning("MISSING HOSTNAME LIST")
        logger.warning(missing_namservers)
    else:
        logger.info("NO MISSING HOSTNAMES")
    logger.info("FINISHED")
    finish_time = time.time()
    logger.info(f"Finish Time: {finish_time}")
    duration = finish_time - start_time
    duration_days = duration // 86400
    duration_hours = (duration % 86400) // 3600
    duration_minutes = (duration % 3600) // 60
    duration_seconds = duration % 60
    logger.info(f"Duration: {duration_days}d {duration_hours}h {duration_minutes}m {duration_seconds}s")
    logger.info(f"Crawl duration: {crawl_duration}s")
    crawl_duration_per_node = crawl_duration / len(nameservers)
    nodes_crawled_per_hour = 3600 / crawl_duration_per_node
    logger.info(f"Average crawl time: {crawl_duration_per_node}s")
    logger.info(f"Est. nodes per hour: {nodes_crawled_per_hour}")
    logger.info(json.dumps(resolver.pydns.stats(), indent=4))

if __name__ == "__main__":
    asyncio.run(compile_nameserver_data("ns_list_test.txt","data","ns-list.jsonl","ns-list.rdf.gz"))

