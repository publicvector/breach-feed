import requests
from bs4 import BeautifulSoup

HEADERS = {'User-Agent': 'Mozilla/5.0'}
resp = requests.get('https://www.ransomware.live/', headers=HEADERS, timeout=60)
soup = BeautifulSoup(resp.text, 'html.parser')
all_links = soup.find_all('a', href=True)

# Find first few /id/ links with their context
for link in all_links[:50]:
    href = link.get('href', '')
    text = link.get_text(strip=True)
    if '/id/' in href or '/map/' in href:
        print(f'=== {href[:50]} ===')
        print(f'Text: {text}')
        # Check for img inside
        img = link.find('img')
        if img:
            alt = img.get('alt', '')
            print(f'  IMG alt: {alt}')
        # Check siblings
        parent = link.parent
        if parent:
            siblings = parent.find_all('a', href=True)
            for sib in siblings:
                if '/map/' in sib.get('href', ''):
                    sib_text = sib.get_text(strip=True)
                    sib_img = sib.find('img')
                    sib_alt = sib_img.get('alt', '') if sib_img else ''
                    print(f'  SIBLING MAP: {sib.get("href")} text="{sib_text}" alt="{sib_alt}"')
