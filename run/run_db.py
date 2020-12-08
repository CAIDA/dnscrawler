from io import StringIO 
import multiprocessing as mp
from concurrent.futures import TimeoutError
from pebble import ProcessPool, ThreadPool
import json
import sys
import shutil
import os
sys.path.append("../")
from dnscrawler import DNSResolver, load_schema, DatabaseConnection
from dnscrawler.logger import log
from glob import glob
import gzip

resolver = DNSResolver()
domain_dict_dirname = "domain_dict"
nodelist_json_dirname = "nodelist"
# Crawl nameserver if it hasn't already been crawled
# and output result to json file
def json_nameserver_file(nameserver,output_dir):
    print(f"Starting: {nameserver}")
    filename = nameserver
    # Create paths and directories for precompiled domain_dicts and nodelist json
    domain_dict_dirpath = f"{output_dir}/{domain_dict_dirname}"
    nodelist_json_dirpath = f"{output_dir}/{nodelist_json_dirname}"
    required_paths = [output_dir, domain_dict_dirpath, nodelist_json_dirpath]
    for dirpath in required_paths:
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)
    # Create paths for domain_dict and nodelist json files
    domain_dict_filepath = f"{output_dir}/{domain_dict_dirname}/{filename}.json"
    nodelist_json_filepath = f"{output_dir}/{nodelist_json_dirname}/{filename}.json"
    if not os.path.exists(domain_dict_filepath):
        data = resolver.get_domain_dict(nameserver, is_ns=True, db_json=True)
        domain_dict = data['domain_dict']
        nodelist_json = data['json']
        with open(domain_dict_filepath,"w") as domain_dict_file, open(nodelist_json_filepath,"w") as nodelist_json_file:
            domain_dict_file.write(json.dumps(domain_dict))
            nodelist_json_file.write(json.dumps(nodelist_json))
    else:
        print(f"File found: {nameserver}")
    print(f"Finished: {nameserver}")

# Handle post crawl operations, mainly the retry preocess
def crawl_complete(future, nameserver, retry_nameservers, retry_file):
    # If crawl is unsuccessful then future.result() will
    # error, so add the unsuccessful ns to the retry list
    # and write to retry file
    try:
        result = future.result()
    except:
        print(f"RETRY HOSTNAME:{nameserver}")
        if nameserver not in retry_nameservers:
            retry_nameservers.append(nameserver)
            retry_file.write(f"{nameserver}\n")
            retry_file.flush()

# Crawl all nameservers from a list in a source file
# and compile their result json into a target file
def compile_nameserver_json(source_file,target_file, db_target_file):
    target_dir = os.path.dirname(target_file)
    target_schema_filepath = target_dir + "/schema.txt"
    print("Resetting database...")
    with DatabaseConnection("localhost:9080") as db, load_schema() as schema_infile, open(target_schema_filepath, "w") as schema_outfile:
        schema = schema_infile.read()
        # TESTING
        db.drop_all()
        db.set_schema(schema)
        schema_outfile.write(schema)
    print("Reading hostname list...")
    with open(source_file,"r") as nsfile:
        nameservers = nsfile.read().splitlines()
    retry_nameservers = []
    retry_filename = target_dir+"/retry.txt"
    with open(retry_filename, 'w') as retry_file:
        with ProcessPool(max_workers=mp.cpu_count()) as pool:
            print("Starting initial crawling...")
            for nameserver in nameservers:
                future = pool.schedule(json_nameserver_file, args=(nameserver,target_dir+"/temp"), timeout=60)
                future.add_done_callback(lambda x: crawl_complete(x,nameserver,retry_nameservers, retry_file)) 
        pool.join()
        with ProcessPool(max_workers=mp.cpu_count()) as pool:
            print("Starting retry crawling")
            print(f"FINAL RETRY LIST: {retry_nameservers}")
            for nameserver in retry_nameservers:
                future = pool.schedule(json_nameserver_file, args=(nameserver,target_dir+"/temp"))
        pool.join()
    print("Compiling data into jsonl file")
    with open(target_file,"wb") as outfile:
        for filename in glob(f"{target_dir}/temp/{domain_dict_dirname}/*.json"):
            with open(filename, "rb") as infile:
                print(f"Compiling file: {filename}")
                outfile.write(infile.read())
                outfile.write('\n'.encode('utf-8'))
                infile.close()
    with gzip.open(db_target_file,"wb") as outfile:
        outfile.write("[".encode('utf-8'))
        file_count = 0
        for filename in glob(f"{target_dir}/temp/{nodelist_json_dirname}/*.json"):
            file_count += 1
            with open(filename, "rb") as infile:
                print(f"Compiling file: {file_count}. {filename}")
                if file_count > 1:
                    outfile.write(','.encode('utf-8'))
                data = infile.read().strip()
                # Remove first and last characters from infile (opening and closing brackets)
                truncated_data = data[1:-1]
                outfile.write(truncated_data)
                infile.close()
        outfile.write("]\n".encode('utf-8'))
    print("FINISHED")

if __name__ == "__main__":
    compile_nameserver_json("gov-domains-test2.txt","data/gov-domains.jsonl","data/db-gov-domains.json.gz")

