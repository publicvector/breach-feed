#!/usr/bin/env python3
"""
Breach Monitor - Generates JSON feed of recent data breaches
Scrapes: ransomware.live
Outputs: breach-feed.json (JSON feed)
"""

import os
import json
import re
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
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
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


def get_ransomware_live_victims(days_back: int = 7) -> list[BreachReport]:
    """Scrape recent victims from ransomware.live"""
    victims = []
    
    try:
        url = "https://www.ransomware.live/"
        response = requests.get(url, headers=HEADERS, timeout=60)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        cutoff_date = (datetime.now() - timedelta(days=days_back)).date()
        
        for link in soup.find_all('a', href=True):
            href = link.get('href', '')
            if '/id/' in href:
                parent = link.parent
                if parent:
                    text_content = parent.get_text()
                    
                    date_match = re.search(r'(\d{4}-\d{2}-\d{2})', text_content)
                    attack_date = date_match.group(1) if date_match else datetime.now().strftime('%Y-%m-%d')
                    
                    if attack_date:
                        try:
                            entry_date = datetime.strptime(attack_date, '%Y-%m-%d').date()
                            if entry_date < cutoff_date:
                                continue
                        except:
                            pass
                    
                    company_name = link.get_text(strip=True)
                    if not company_name:
                        continue
                    
                    # Find ransomware group
                    group_name = "Unknown"
                    for group_link in soup.find_all('a', href=True):
                        if '/group/' in group_link.get('href', ''):
                            group_text = group_link.get_text(strip=True)
                            if group_text and group_text in text_content:
                                group_name = group_text
                                break
                    
                    # Find location
                    location = "Unknown"
                    for flag in parent.find_all('img'):
                        alt = flag.get('alt', '')
                        if alt and len(alt) == 2:
                            location = alt
                            break
                    
                    # Victim count
                    victims_match = re.search(r'(\d[\d,]*)', text_content)
                    victim_count = victims_match.group(1) if victims_match else "Unknown"
                    
                    # Sensitive data
                    data_at_risk = extract_sensitive_data(text_content)
                    
                    # Check threshold
                    include = True
                    if victim_count != "Unknown":
                        try:
                            count = int(victim_count.replace(',', ''))
                            if count < MIN_VICTIMS and not data_at_risk:
                                include = False
                        except:
                            pass
                    
                    if include and company_name:
                        victims.append(BreachReport(
                            company_name=company_name,
                            location=location,
                            victims=victim_count,
                            data_at_risk=data_at_risk if data_at_risk else "Data exfiltrated",
                            attack_date=attack_date,
                            ransomware_group=group_name,
                            source="ransomware.live",
                            url=f"https://www.ransomware.live{href}",
                            description=text_content[:500]
                        ))
        
        seen = set()
        unique = []
        for v in victims:
            if v.company_name not in seen:
                seen.add(v.company_name)
                unique.append(v)
        victims = unique[:30]
        
    except Exception as e:
        print(f"Error fetching ransomware.live: {e}")
    
    return victims


def extract_sensitive_data(description: str) -> str:
    """Extract sensitive data types from description"""
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


def generate_json_feed(breaches: list[BreachReport]) -> dict:
    """Generate JSON feed"""
    return {
        "version": "https://jsonfeed.org/version/1",
        "title": "Data Breach Alerts",
        "home_page_url": "https://www.ransomware.live",
        "feed_url": f"file://{JSON_PATH}",
        "description": "Automated feed of recent data breaches and ransomware attacks affecting 10,000+ people or involving sensitive data",
        "generated_at": datetime.now().isoformat(),
        "items": [asdict(b) for b in breaches]
    }


def generate_html_view(breaches: list[BreachReport]) -> str:
    """Generate simple HTML view"""
    
    rows = ""
    for b in breaches:
        # Color code by sensitivity
        if "PHI" in b.data_at_risk or "Health" in b.data_at_risk or "Medical" in b.data_at_risk:
            row_class = "sensitive-health"
        elif "SSN" in b.data_at_risk or "Passport" in b.data_at_risk:
            row_class = "sensitive-id"
        elif b.victims != "Unknown" and int(b.victims.replace(',', '')) > 100000:
            row_class = "high-volume"
        else:
            row_class = ""
        
        rows += f"""
        <tr class="{row_class}">
            <td><a href="{b.url}" target="_blank">{b.company_name}</a></td>
            <td>{b.location}</td>
            <td>{b.victims}</td>
            <td>{b.data_at_risk}</td>
            <td>{b.attack_date}</td>
            <td>{b.ransomware_group}</td>
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
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f8f8; font-weight: 600; }}
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
        Source: <a href="https://www.ransomware.live" target="_blank">ransomware.live</a>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Company</th>
                <th>Location</th>
                <th>Victims</th>
                <th>Data at Risk</th>
                <th>Attack Date</th>
                <th>Attacker</th>
            </tr>
        </thead>
        <tbody>
{rows}
        </tbody>
    </table>
    
    <div class="legend">
        <span style="background:#fff0f0">Health/PHI</span>
        <span style="background:#fff8e0">ID Docs (SSN, Passport)</span>
        <span style="background:#f0f0ff">100k+ Victims</span>
    </div>
</body>
</html>"""
    
    return html


def main():
    print(f"[*] Running breach monitor - {datetime.now()}")
    
    # Fetch breaches
    print("[*] Fetching from ransomware.live...")
    breaches = get_ransomware_live_victims(days_back=7)
    print(f"    Found {len(breaches)} breaches")
    
    # Print to console
    for b in breaches:
        print(f"  - {b.company_name} ({b.location}) | {b.ransomware_group} | {b.victims} victims")
    
    # Generate JSON
    print(f"\n[*] Generating JSON feed...")
    feed = generate_json_feed(breaches)
    
    with open(JSON_PATH, 'w') as f:
        json.dump(feed, f, indent=2)
    print(f"    Saved to: {JSON_PATH}")
    
    # Generate HTML view
    print("[*] Generating HTML view...")
    html = generate_html_view(breaches)
    
    with open(HTML_PATH, 'w') as f:
        f.write(html)
    print(f"    Saved to: {HTML_PATH}")
    
    # Also save the old RSS
    print("[*] Generating RSS feed...")
    import subprocess
    try:
        subprocess.run(['python3', os.path.join(OUTPUT_DIR, 'breach_feed.py')], 
                      capture_output=True, cwd=OUTPUT_DIR)
    except:
        pass
    
    print(f"\n[*] Done! Files created:")
    print(f"    - {JSON_PATH}")
    print(f"    - {HTML_PATH}")
    print(f"    - {OUTPUT_DIR}/breach-feed.xml")
    print(f"\n[*] Open {HTML_PATH} in a browser for easy viewing")


if __name__ == "__main__":
    main()
