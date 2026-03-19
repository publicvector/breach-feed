#!/usr/bin/env python3
"""
Breach Monitor - Multi-source breach monitoring with company enrichment
Sources: ransomware.live, breachsense, hipaajournal
Company info: Wikipedia + search
"""

import os
import json
import re
import time
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import warnings
warnings.filterwarnings('ignore')

OUTPUT_DIR = os.path.expanduser("~/breach-monitor")
JSON_PATH = os.path.join(OUTPUT_DIR, "breach-feed.json")
HTML_PATH = os.path.join(OUTPUT_DIR, "breach-feed.html")

MIN_VICTIMS = 10000

SENSITIVE_DATA_KEYWORDS = [
    "ssn", "social security", "passport", "driver license", "credit card",
    "bank account", "financial", "health", "medical", "phi", "patient",
    "insurance", "medicare", "dob", "date of birth", "email", "password",
    "credentials", "tax id", "ein"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


@dataclass
class BreachReport:
    company_name: str
    location: str
    victims: str
    data_at_risk: str
    attack_date: str
    ransomware_group: str
    source: str
    url: str
    description: str
    company_description: str
    industry: str


def search_company_info(company_name: str) -> dict:
    """Get company info from Wikipedia and guess from name"""
    info = {"description": "", "industry": ""}
    
    # First, try to guess industry from company name
    name_lower = company_name.lower()
    
    # Industry keywords in company name
    industry_patterns = {
        "Healthcare": ["hospital", "health", "medical", "clinic", "pharma", "pharmacy", "dental", "care", "clinical", "diagnostic"],
        "Financial Services": ["bank", "financial", "insurance", "credit", "capital", "investment", "trust", "securities", "loan"],
        "Technology": ["tech", "software", "systems", "digital", "data", "cloud", "cyber", "it ", " solutions"],
        "Government": ["government", "municipal", "city", "county", "state", "federal", "court", "cad", "assessment"],
        "Education": ["school", "university", "college", "academy", "education", "training"],
        "Manufacturing": ["manufacturing", "industrial", "metal", "steel", "chemical", "plastics", "equipment", "parts"],
        "Retail": ["retail", "store", "shop", "market", "distribution", "wholesale"],
        "Transportation": ["transport", "logistics", "shipping", "trucking", "airline", "aviation", "freight"],
        "Energy": ["energy", "electric", "power", "gas", "oil", "solar", "renewable"],
        "Construction": ["construction", "building", "contractor", "architecture", "engineering", "real estate"]
    }
    
    for industry, patterns in industry_patterns.items():
        if any(p in name_lower for p in patterns):
            info["industry"] = industry
            break
    
    # Try Wikipedia API
    try:
        # Clean company name for Wikipedia
        wiki_name = company_name.split('@')[0].strip()  # Remove @group
        wiki_name = re.sub(r'\.com|\.org|\.net|\.io|\.co$', '', wiki_name)  # Remove TLD
        wiki_url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{requests.utils.quote(wiki_name)}"
        resp = requests.get(wiki_url, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            desc = data.get("description", "") or data.get("extract", "")[:200]
            if desc and "may refer to" not in desc and "Topics referred" not in desc:
                info["description"] = desc
                # Override industry if Wikipedia gives better info
                desc_lower = desc.lower()
                for industry, patterns in industry_patterns.items():
                    if any(p in desc_lower for p in patterns):
                        info["industry"] = industry
                        break
    except:
        pass
    
    return info


def get_victim_details(url: str) -> dict:
    """Fetch detailed info from a victim's page"""
    try:
        clean_url = url.split('#')[0]
        resp = requests.get(clean_url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        details = {}
        text = soup.get_text()
        
        # Extract victim count
        for pattern in [r'(\d[\d,]*)\s*victims?', r'(\d[\d,]*)\s*records? leaked']:
            match = re.search(pattern, text, re.I)
            if match:
                details['victims'] = match.group(1)
                break
        
        # Extract ransomware group
        for link in soup.find_all('a', href=True):
            if '/group/' in link.get('href', ''):
                group = link.get_text(strip=True)
                if group and len(group) < 30:
                    details['ransomware_group'] = group
                    break
        
        # Extract country
        for link in soup.find_all('a', href=True):
            if '/map/' in link.get('href', ''):
                country = link.get_text(strip=True)
                if country and len(country) <= 3:
                    details['location'] = country
                    break
        
        # Extract dates
        dates = re.findall(r'(\d{4}-\d{2}-\d{2})', text)
        if dates:
            details['attack_date'] = dates[0]
        
        return details
    except:
        return {}


def get_ransomware_live_victims(days_back: int = 3) -> list[BreachReport]:
    """Scrape ransomware.live"""
    victims = []
    seen_urls = set()
    
    try:
        print("[*] Fetching ransomware.live...")
        resp = requests.get("https://www.ransomware.live/", headers=HEADERS, timeout=60)
        soup = BeautifulSoup(resp.text, 'html.parser')
        cutoff_date = (datetime.now() - timedelta(days=days_back)).date()
        
        # Get victim URLs
        for link in soup.find_all('a', href=True):
            if '/id/' in link.get('href', ''):
                clean = link.get('href', '').split('#')[0]
                full_url = f"https://www.ransomware.live{clean}"
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
        
        print(f"    Found {len(seen_urls)} victims, fetching details...")
        
        for i, victim_url in enumerate(list(seen_urls)[:15]):
            print(f"    [{i+1}/15] Processing...")
            
            # Decode company name
            try:
                import base64
                encoded = victim_url.split('/id/')[-1]
                encoded = encoded.replace('-', '+').replace('_', '/')
                padding = 4 - len(encoded) % 4
                if padding != 4:
                    encoded += '=' * padding
                company_name = re.sub(r'@.+$', '', base64.b64decode(encoded).decode('utf-8'))
            except:
                company_name = "Unknown"
            
            details = get_victim_details(victim_url)
            
            # Get company info
            company_info = search_company_info(company_name)
            
            # Sensitive data check
            desc_text = company_info.get("description", "")
            data_at_risk = extract_sensitive_data(desc_text)
            
            attack_date = details.get('attack_date', datetime.now().strftime('%Y-%m-%d'))
            
            victims.append(BreachReport(
                company_name=company_name,
                location=details.get('location', 'Unknown'),
                victims=details.get('victims', 'Unknown'),
                data_at_risk=data_at_risk if data_at_risk else "Data exfiltrated",
                attack_date=attack_date,
                ransomware_group=details.get('ransomware_group', 'Unknown'),
                source="ransomware.live",
                url=victim_url,
                description="",
                company_description=company_info.get("description", ""),
                industry=company_info.get("industry", "")
            ))
            
            time.sleep(0.3)
    
    except Exception as e:
        print(f"Error: {e}")
    
    return victims


def get_breachsense_breaches() -> list[BreachReport]:
    """Scrape breachsense.com"""
    breaches = []
    
    try:
        print("[*] Fetching breachsense...")
        # Get recent breaches page
        month = datetime.now().strftime("%Y/%m").lower()
        url = f"https://www.breachsense.com/breaches/{month}/"
        resp = requests.get(url, headers=HEADERS, timeout=60)
        
        if resp.status_code != 200:
            # Try without month
            url = "https://www.breachsense.com/breaches/"
            resp = requests.get(url, headers=HEADERS, timeout=60)
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        for article in soup.find_all('article')[:15]:
            link = article.find('a', href=True)
            if not link:
                continue
            
            href = link.get('href', '')
            title = link.get_text(strip=True)
            
            if not title or 'breach' in href.lower():
                continue
            
            # Get description
            desc = article.get_text(strip=True)
            
            # Extract info
            actor_match = re.search(r'Threat Actor[:\s]+([A-Za-z]+)', desc)
            count_match = re.search(r'(\d[\d,]*)\s*(?:records?|users?|people)', desc, re.I)
            
            # Get company info
            company_info = search_company_info(title)
            
            data_at_risk = extract_sensitive_data(desc) or extract_sensitive_data(company_info.get("description", ""))
            
            breaches.append(BreachReport(
                company_name=title,
                location="Unknown",
                victims=count_match.group(1) if count_match else "Unknown",
                data_at_risk=data_at_risk if data_at_risk else "Data exposed",
                attack_date=datetime.now().strftime('%Y-%m-%d'),
                ransomware_group=actor_match.group(1) if actor_match else "Unknown",
                source="breachsense",
                url=href,
                description=desc[:200],
                company_description=company_info.get("description", ""),
                industry=company_info.get("industry", "")
            ))
    
    except Exception as e:
        print(f"    Error: {e}")
    
    return breaches[:10]


def get_hipaa_breaches() -> list[BreachReport]:
    """Scrape hipaajournal breach news"""
    breaches = []
    
    try:
        print("[*] Fetching hipaajournal...")
        url = "https://www.hipaajournal.com/category/hipaa-breach-news/"
        resp = requests.get(url, headers=HEADERS, timeout=60)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        for article in soup.find_all(['article', 'div'], class_=['', 'post', 'entry'])[:15]:
            # Look for links
            link = article.find('a', href=True)
            if not link:
                continue
            
            title_link = None
            for a in article.find_all('a'):
                if a.get_text(strip=True) and len(a.get_text(strip=True)) > 5:
                    title_link = a
                    break
            
            if not title_link:
                continue
            
            title = title_link.get_text(strip=True)
            href = title_link.get('href', '')
            
            if not title or 'breach' not in href.lower():
                continue
            
            # Get description
            desc = article.get_text(strip=True)[:300]
            
            # Get company info
            company_info = search_company_info(title)
            
            data_at_risk = extract_sensitive_data(desc) or "PHI (Health Data)"
            
            breaches.append(BreachReport(
                company_name=title,
                location="US",  # HIPAA breaches are mostly US
                victims="Unknown",
                data_at_risk=data_at_risk,
                attack_date=datetime.now().strftime('%Y-%m-%d'),
                ransomware_group="Unknown",
                source="hipaajournal",
                url=href,
                description=desc,
                company_description=company_info.get("description", ""),
                industry=company_info.get("industry", "Healthcare")
            ))
    
    except Exception as e:
        print(f"    Error: {e}")
    
    return breaches[:10]


def extract_sensitive_data(description: str) -> str:
    if not description:
        return ""
    desc_lower = description.lower()
    found = []
    mapping = {
        "ssn": "SSN", "social security": "Social Security Numbers",
        "passport": "Passport Numbers", "driver license": "Driver's License",
        "credit card": "Credit Card Info", "bank account": "Bank Account Details",
        "health": "Health Data", "medical": "Medical Data", "phi": "PHI",
        "patient": "Patient Records", "insurance": "Insurance Info",
        "dob": "Date of Birth", "date of birth": "Date of Birth",
        "email": "Email Addresses", "password": "Passwords",
        "credentials": "Credentials", "ein": "EIN", "tax id": "Tax ID"
    }
    for kw, display in mapping.items():
        if kw in desc_lower and display not in found:
            found.append(display)
    return ", ".join(found) if found else ""


def generate_html_view(breaches: list[BreachReport]) -> str:
    rows = ""
    for b in breaches:
        # Color coding
        if "PHI" in b.data_at_risk or "Health" in b.data_at_risk or "Medical" in b.data_at_risk or b.industry == "Healthcare":
            row_class = "sensitive-health"
        elif "SSN" in b.data_at_risk or "Passport" in b.data_at_risk:
            row_class = "sensitive-id"
        elif b.victims != "Unknown":
            try:
                if int(b.victims.replace(',', '')) > 100000:
                    row_class = "high-volume"
                else:
                    row_class = ""
            except:
                row_class = ""
        else:
            row_class = ""
        
        # Show company description or industry
        display_info = b.company_description[:80] + "..." if b.company_description and len(b.company_description) > 80 else b.company_description
        if b.industry and b.industry not in str(display_info):
            display_info = f"[{b.industry}] {display_info}" if display_info else f"[{b.industry}]"
        
        victims_display = b.victims if b.victims != "Unknown" else "—"
        
        rows += f"""
        <tr class="{row_class}">
            <td><a href="{b.url}" target="_blank">{b.company_name}</a></td>
            <td>{b.industry if b.industry else '—'}</td>
            <td>{b.location}</td>
            <td>{victims_display}</td>
            <td>{b.data_at_risk}</td>
            <td>{b.attack_date}</td>
            <td>{b.ransomware_group}</td>
            <td>{display_info}</td>
        </tr>
"""
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Data Breach Alerts</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        h1 {{ color: #333; }}
        .meta {{ color: #666; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f8f8; font-weight: 600; font-size: 12px; }}
        td {{ font-size: 12px; }}
        tr:hover {{ background: #fafafa; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .sensitive-health {{ background: #fff0f0; }}
        .sensitive-id {{ background: #fff8e0; }}
        .high-volume {{ background: #f0f0ff; }}
        .legend {{ margin-top: 20px; font-size: 14px; color: #666; }}
        .legend span {{ display: inline-block; padding: 2px 8px; margin-right: 10px; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>🚨 Data Breach Alerts</h1>
    <div class="meta">
        Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        Sources: ransomware.live, breachsense, hipaajournal
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Company</th>
                <th>Industry</th>
                <th>Location</th>
                <th>Victims</th>
                <th>Data at Risk</th>
                <th>Date</th>
                <th>Attacker</th>
                <th>Company Info</th>
            </tr>
        </thead>
        <tbody>
{rows}
        </tbody>
    </table>
    
    <div class="legend">
        <span style="background:#fff0f0">Healthcare/PHI</span>
        <span style="background:#fff8e0">ID Docs</span>
        <span style="background:#f0f0ff">100k+ Victims</span>
    </div>
</body>
</html>"""
    return html


def generate_json_feed(breaches: list[BreachReport]) -> dict:
    return {
        "version": "https://jsonfeed.org/version/1",
        "title": "Data Breach Alerts",
        "generated_at": datetime.now().isoformat(),
        "items": [asdict(b) for b in breaches]
    }


def main():
    print(f"[*] Running breach monitor - {datetime.now()}")
    
    all_breaches = []
    
    # Get from each source
    all_breaches.extend(get_ransomware_live_victims(days_back=3))
    all_breaches.extend(get_breachsense_breaches())
    all_breaches.extend(get_hipaa_breaches())
    
    # Remove duplicates by company name
    seen = set()
    unique = []
    for b in all_breaches:
        key = b.company_name.lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append(b)
    
    breaches = unique[:30]  # Limit to 30
    
    print(f"\n[*] Total: {len(breaches)} unique breaches")
    for b in breaches[:10]:
        print(f"  - {b.company_name} ({b.industry}) | {b.ransomware_group}")
    if len(breaches) > 10:
        print(f"  ... and {len(breaches) - 10} more")
    
    # Save files
    feed = generate_json_feed(breaches)
    with open(JSON_PATH, 'w') as f:
        json.dump(feed, f, indent=2)
    print(f"\n[*] JSON: {JSON_PATH}")
    
    html = generate_html_view(breaches)
    with open(HTML_PATH, 'w') as f:
        f.write(html)
    print(f"[*] HTML: {HTML_PATH}")


if __name__ == "__main__":
    main()
