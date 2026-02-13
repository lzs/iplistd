#!/usr/bin/env python3
import argparse
import sys
from dotenv import load_dotenv
import os
import requests
from vault import vault_read

load_dotenv()

def main():
    parser = argparse.ArgumentParser(description="IP list management.")
    parser.add_argument("ip_address", help="IP address to add")
    parser.add_argument("timeout", type=int, nargs="?", default=86400, help="Timeout in seconds (default: 86400)")
    parser.add_argument("reason", nargs="?", default="default", help="Reason for shunning (default: 'default')")

    args = parser.parse_args()

    iplist_addr = os.getenv("IPLIST_ADDR")
    iplist_ns = os.getenv("IPLIST_NS")
    iplist_path = os.getenv("IPLIST_PATH")

    if not iplist_addr:
        print("Error: IPLIST_ADDR environment variable is required.", file=sys.stderr)
        sys.exit(1)
    if not iplist_ns:
        print("Error: IPLIST_NS environment variable is required.", file=sys.stderr)
        sys.exit(1)
    if not iplist_path:
        print("Error: IPLIST_PATH environment variable is required.", file=sys.stderr)
        sys.exit(1)

    # Fetch API key from Vault
    apikey = vault_read(namespace=iplist_ns, secret_path=iplist_path, field='apikey')
    if not apikey:
        print("Error: Could not retrieve API key from Vault.", file=sys.stderr)
        sys.exit(1)

    url = f"{iplist_addr.rstrip('/')}/ip-filters/"
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {apikey}',
        'Content-Type': 'application/json'
    }
    data = {
        "ip_address": args.ip_address,
        "timeout_seconds": args.timeout,
        "reason": args.reason
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        # Check if the request was successful
        # The original script didn't check status, but it's good practice.
        # However, to mimic 'curl' outputting the body regardless of status:
        print(response.text)
        
        # If you want to enforce success:
        # response.raise_for_status() 
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
