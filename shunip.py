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
    parser.add_argument("timeout", type=int, nargs="?", default=1440, help="Timeout in minutes (default: 1440)")
    parser.add_argument("reason", nargs="?", default="default", help="Reason for shunning (default: 'default')")

    args = parser.parse_args()

    # Fetch API key from Vault
    apikey = vault_read(namespace='infra', secret_path='nw/shunip', field='apikey')
    if not apikey:
        print("Error: Could not retrieve API key from Vault.", file=sys.stderr)
        sys.exit(1)

    print(f"API Key: {apikey}")
    url = 'https://jdata1.comp.nus.edu.sg/ip-filters/'
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {apikey}',
        'Content-Type': 'application/json'
    }
    data = {
        "ip_address": args.ip_address,
        "timeout_minutes": args.timeout,
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
