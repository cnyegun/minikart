#!/usr/bin/env python3
import redis
import pickle
import sys

def main():
    # decode_responses=False is required to handle raw binary bytes
    client = redis.Redis(host='localhost', port=6379, decode_responses=False)

    data = {
        "id": 42,
        "name": "Binary Test",
        "flags": [0x00, 0xFF, 0xAB],
        "active": True
    }

    # Serialize object to bytes
    packed_data = pickle.dumps(data)
    key = "session:42"

    print(f"Storing {len(packed_data)} bytes of binary data...")
    client.set(key, packed_data)

    # Retrieve and Deserialize
    retrieved_raw = client.get(key)
    
    if not retrieved_raw:
        print("Error: Failed to retrieve key")
        sys.exit(1)

    restored_data = pickle.loads(retrieved_raw)

    # Verification
    if restored_data["flags"] == data["flags"]:
        print("Binary serialization verification passed.")
    else:
        print("Error: Data corruption detected")

if __name__ == "__main__":
    main()
