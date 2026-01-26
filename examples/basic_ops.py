#!/usr/bin/env python3
import redis
import sys

def main():
    # Connect to Minikart (default port 6379)
    # decode_responses=True ensures we get strings back, not bytes
    client = redis.Redis(host='localhost', port=6379, decode_responses=True)

    try:
        if not client.ping():
            print("Error: PING failed.")
            sys.exit(1)
    except redis.exceptions.ConnectionError:
        print("Error: Could not connect to Minikart on localhost:6379.")
        sys.exit(1)

    # 1. Clear database
    client.flushdb()

    # 2. Key-Value Operations
    key = "user:1001"
    value = "minikart_user"
    
    client.set(key, value)
    stored_value = client.get(key)
    
    if stored_value != value:
        print(f"Mismatch: Expected '{value}', got '{stored_value}'")
        sys.exit(1)

    # 3. DBSIZE check
    size = client.dbsize()
    print(f"DBSIZE: {size}")

    # 4. Deletion
    deleted = client.delete(key)
    if deleted != 1:
        print("Error: DELETE return value incorrect")
    
    if client.get(key) is not None:
        print("Error: Key was not deleted")

    print("Basic operations verification passed.")

if __name__ == "__main__":
    main()