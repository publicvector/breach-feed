#!/usr/bin/env python3
"""
Breach Monitor - Generates RSS feed of recent data breaches
Scrapes: ransomware.live
Outputs: breach-feed.xml (RSS 2.0)
"""

import os
import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from dataclasses import dataclass
import warnings
warnings.filterwarnings('ignore')

OUTPUT_DIR = os.path.expanduser("~/breach-monitor")
FEED_PATH = os.path.join(OUTPUT_DIR, "breach-feed.xml")

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


def get_ransomware_live_victims(days_back: int = 3) -> list[BreachReport]:
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


def generate_rss_feed(breaches: list[BreachReport]) -> str:
    """Generate RSS 2.0 feed"""
    
    items = ""
    for b in breaches:
        # Try to format date properly
        try:
            dt = datetime.strptime(b.attack_date, '%Y-%m-%d')
            pub_date = dt.strftime('%a, %d %b %Y %H:%M:%S GMT')
        except:
            pub_date = datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        # Build description
        desc = f"""
<b>Company:</b> {b.company_name}<br/>
<b>Location:</b> {b.location}<br/>
<b>Victims:</b> {b.victims}<br/>
<b>Data at Risk:</b> {b.data_at_risk}<br/>
<b>Attack Date:</b> {b.attack_date}<br/>
<b>Ransomware Group:</b> {b.ransomware_group}<br/>
<b>Source:</b> {b.source}<br/>
<br/>
<b>Description:</b> {b.description}
        """.strip()
        
        items += f"""
    <item>
        <title><![CDATA[{b.company_name} - {b.ransomware_group}]]></title>
        <link>{b.url}</link>
        <guid isPermaLink="true">{b.url}</guid>
        <pubDate>{pub_date}</pubDate>
        <description><![CDATA[{desc}]]></description>
    </item>
"""
    
    rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
    <channel>
        <title>Data Breach Alerts</title>
        <link>https://www.ransomware.live</link>
        <description>Automated feed of recent data breaches and ransomware attacks affecting 10,000+ people or involving sensitive data (SSN, health info, etc.)</description>
        <language>en-us</language>
        <lastBuildDate>{datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}</lastBuildDate>
        <atom:link href="file://{FEED_PATH}" rel="self" type="application/rss+xml"/>
        <generator>Breach Monitor v1.0</generator>
{items}
    </channel>
</rss>"""
    
    return rss


def main():
    print(f"[*] Running breach monitor - {datetime.now()}")
    
    # Fetch breaches
    print("[*] Fetching from ransomware.live...")
    breaches = get_ransomware_live_victims(days_back=7)
    print(f"    Found {len(breaches)} breaches")
    
    # Print to console
    for b in breaches:
        print(f"  - {b.company_name} ({b.location}) | {b.ransomware_group} | {b.victims} victims")
    
    # Generate RSS
    print(f"\n[*] Generating RSS feed...")
    rss = generate_rss_feed(breaches)
    
    with open(FEED_PATH, 'w') as f:
        f.write(rss)
    
    print(f"    Saved to: {FEED_PATH}")
    print(f"\n[*] To subscribe: import this RSS feed into Feedly, Microsoft Reader, or any RSS client")


if __name__ == "__main__":
    main()
