import requests
import time

url = "http://localhost:8080/products"
success_count = 0
blocked_count = 0
other_count = 0

print(f"Testing rate limiting on {url}...")

for i in range(100):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            success_count += 1
        elif response.status_code == 429:
            blocked_count += 1
        else:
            other_count += 1
            print(f"Request {i+1}: Status {response.status_code}")
    except Exception as e:
        print(f"Request {i+1}: Error {e}")

print(f"Results: Success={success_count}, Blocked={blocked_count}, Other={other_count}")
