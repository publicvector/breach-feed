#!/usr/bin/env python3
import requests
url = 'https://api.ransomware.live/v2/victims'
resp = requests.get(url, timeout=30)
print(f'Status: {resp.status_code}')
print(f'Content: {resp.text[:500]}')
