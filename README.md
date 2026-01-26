# minikart
![Language](https://img.shields.io/badge/language-C23-blue)
![License](https://img.shields.io/badge/license-GNU-GPLv3)

Minikart is a single-threaded, event-driven Redis clone.
It is *faster* than official Redis.

It implements the RESP protocol and uses an [Adaptive Radix Tree](https://www.db.in.tum.de/~leis/papers/ART.pdf) for the keyspace instead of a traditional hash table. 

This allows for efficient prefix lookups and stable latency.

## Benchmark
**Command**: `redis-benchmark -p 6379 -t set,get -n 100000 --csv`
| Server | SET (Requests/sec) | GET (Requests/sec) | Avg Latency |
| :--- | :--- | :--- | :--- |
| Minikart | 118,764.84 | 117,096.02 | 0.222 ms |
| Official Redis | 111,982.08 | 114,810.56 | 0.234 ms |

## Supported Commands
- `SET`, `GET`, `DEL`
- `KEYS`
- `DBSIZE`, `FLUSH`, `PING`

## Python Compatibility

Minikart is fully compatible with the standard `redis` library. You can use it as a drop-in replacement for supported commands.

```python
import redis

# Connect to Minikart (default port 6379)
# decode_responses=True returns strings instead of bytes
r = redis.Redis(host='localhost', port=6379, decode_responses=True)

r.set("framework", "minikart")
print(f"Stored: {r.get('framework')}")

# Optimized Prefix Search
# This uses the ART tree's native prefix iteration
keys = r.keys("frame*")
print(f"Found keys: {keys}")

# Stats
print(f"Database Size: {r.dbsize()}")
```
## Build
```bash
git clone https://github.com/cnyegun/minikart
cd minikart
make
```
