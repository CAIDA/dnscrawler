from io import StringIO 
import multiprocessing as mp
from concurrent.futures import TimeoutError
from pebble import ProcessPool, ThreadPool
import json
import sys
import shutil
import os
sys.path.append("../")
from dnscrawler import DNSResolver
from dnscrawler.logger import log
from glob import glob

resolver = DNSResolver()
# Crawl nameserver if it hasn't already been crawled
# and output result to json file
def json_nameserver_file(nameserver,output_dir):
    print(f"Starting: {nameserver}")
    filename = nameserver
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    filepath = output_dir+"/"+filename+".json"
    if not os.path.exists(filepath):
        domain_dict = resolver.get_domain_dict(nameserver, isNS=True)
        f = open(filepath,"w")
        f.write(json.dumps(domain_dict))
        f.close()
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
def compile_nameserver_json(source_file,target_file):
    print("Reading hostname list...")
    with open(source_file,"r") as nsfile:
        nameservers = nsfile.read().splitlines()
    target_dir = os.path.dirname(target_file)
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
        for filename in glob(target_dir+"/temp/*.json"):
            with open(filename, "rb") as infile:
                print(f"Compiling file: {filename}")
                outfile.write(infile.read())
                outfile.write('\n'.encode('utf-8'))
                infile.close()
    print("FINISHED")

if __name__ == "__main__":
    compile_nameserver_json("new_domains.csv","data/new_domains.jsonl")

