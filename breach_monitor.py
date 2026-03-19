#!/usr/bin/env python3
"""
Breach Monitor - Clean, readable output
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
    info = {"description": "", "industry": ""}
    name_lower = company_name.lower()
    
    industry_patterns = {
        "🏥 Healthcare": ["hospital", "health", "medical", "clinic", "pharma", "pharmacy", "dental", "care", "clinical"],
        "🏦 Financial": ["bank", "financial", "insurance", "credit", "capital", "investment", "trust", "securities"],
        "💻 Technology": ["tech", "software", "systems", "digital", "data", "cloud", "cyber"],
        "🏛️ Government": ["government", "municipal", "city", "county", "state", "federal", "court", "cad"],
        "🎓 Education": ["school", "university", "college", "academy", "education"],
        "🏭 Manufacturing": ["manufacturing", "industrial", "metal", "steel", "chemical", "equipment", "parts"],
        "🏪 Retail": ["retail", "store", "shop", "market", "distribution"],
        "✈️ Transportation": ["transport", "logistics", "shipping", "trucking", "airline", "aviation", "freight"],
        "⚡ Energy": ["energy", "electric", "power", "gas", "oil", "solar"],
        "🏗️ Construction": ["construction", "building", "contractor", "architecture", "engineering", "real estate"]
    }
    
    for industry, patterns in industry_patterns.items():
        if any(p in name_lower for p in patterns):
            info["industry"] = industry
            break
    
    try:
        wiki_name = company_name.split('@')[0].strip()
        wiki_name = re.sub(r'\.com|\.org|\.net|\.io|\.co$', '', wiki_name)
        wiki_url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{requests.utils.quote(wiki_name)}"
        resp = requests.get(wiki_url, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            desc = data.get("description", "") or data.get("extract", "")[:200]
            if desc and "may refer to" not in desc and "Topics referred" not in desc:
                info["description"] = desc
    except:
        pass
    
    return info


def get_victim_details(url: str) -> dict:
    try:
        clean_url = url.split('#')[0]
        resp = requests.get(clean_url, headers=HEADERS, timeout=30)
        soup = BeautifulSoup(resp.text, 'html.parser')
        text = soup.get_text()
        
        details = {}
        
        for pattern in [r'(\d[\d,]*)\s*victims?', r'(\d[\d,]*)\s*records?']:
            match = re.search(pattern, text, re.I)
            if match:
                details['victims'] = match.group(1)
                break
        
        for link in soup.find_all('a', href=True):
            if '/group/' in link.get('href', ''):
                group = link.get_text(strip=True)
                if group and len(group) < 30:
                    details['ransomware_group'] = group
                    break
        
        for link in soup.find_all('a', href=True):
            if '/map/' in link.get('href', ''):
                country = link.get_text(strip=True)
                if country and len(country) <= 3:
                    details['location'] = country
                    break
        
        dates = re.findall(r'(\d{4}-\d{2}-\d{2})', text)
        if dates:
            details['attack_date'] = dates[0]
        
        return details
    except:
        return {}


def get_ransomware_live_victims(days_back: int = 3) -> list[BreachReport]:
    victims = []
    seen_urls = set()
    
    try:
        print("[*] Fetching ransomware.live...")
        resp = requests.get("https://www.ransomware.live/", headers=HEADERS, timeout=60)
        soup = BeautifulSoup(resp.text, 'html.parser')
        cutoff_date = (datetime.now() - timedelta(days=days_back)).date()
        
        for link in soup.find_all('a', href=True):
            if '/id/' in link.get('href', ''):
                clean = link.get('href', '').split('#')[0]
                full_url = f"https://www.ransomware.live{clean}"
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
        
        print(f"    Found {len(seen_urls)} victims")
        
        for i, victim_url in enumerate(list(seen_urls)[:20]):
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
            company_info = search_company_info(company_name)
            
            attack_date = details.get('attack_date', datetime.now().strftime('%Y-%m-%d'))
            
            victims.append(BreachReport(
                company_name=company_name,
                location=details.get('location', '🌍'),
                victims=details.get('victims', '—'),
                data_at_risk="📦 Data exfiltrated",
                attack_date=attack_date,
                ransomware_group=details.get('ransomware_group', 'Unknown'),
                source="ransomware.live",
                url=victim_url,
                description="",
                company_description=company_info.get("description", ""),
                industry=company_info.get("industry", "")
            ))
            
            time.sleep(0.2)
    
    except Exception as e:
        print(f"Error: {e}")
    
    return victims


def extract_sensitive_data(description: str) -> str:
    if not description:
        return ""
    desc_lower = description.lower()
    found = []
    
    mapping = {
        "ssn": "🔐 SSN", "social security": "🔐 Social Security Numbers",
        "passport": "🛂 Passport", "driver license": "🪪 Driver's License",
        "credit card": "💳 Credit Card", "bank account": "🏦 Bank Account",
        "health": "🏥 Health Data", "medical": "🏥 Medical Data", "phi": "🏥 PHI",
        "patient": "🏥 Patient Records", "insurance": "🏥 Insurance",
        "dob": "📅 Date of Birth", "email": "📧 Email Addresses",
        "password": "🔑 Passwords", "credentials": "🔑 Credentials"
    }
    
    for kw, display in mapping.items():
        if kw in desc_lower and display not in found:
            found.append(display)
    
    return " | ".join(found) if found else "📦 Data exfiltrated"


def generate_html_view(breaches: list[BreachReport]) -> str:
    # Group by date
    by_date = {}
    for b in breaches:
        date = b.attack_date
        if date not in by_date:
            by_date[date] = []
        by_date[date].append(b)
    
    date_blocks = ""
    for date in sorted(by_date.keys(), reverse=True):
        items = by_date[date]
        
        item_rows = ""
        for b in items:
            # Badge styles
            if "🏥" in (b.industry or ""):
                badge = "badge-health"
            elif "🏦" in (b.industry or ""):
                badge = "badge-financial"
            elif "🏛️" in (b.industry or ""):
                badge = "badge-gov"
            else:
                badge = "badge-default"
            
            industry = f'<span class="badge {badge}">{b.industry}</span>' if b.industry else '<span class="badge">—</span>'
            
            # Company description
            desc = b.company_description[:100] + "..." if b.company_description and len(b.company_description) > 100 else b.company_description
            desc_html = f'<div class="company-desc">{desc}</div>' if desc else ""
            
            item_rows += f'''
            <div class="breach-card">
                <div class="breach-header">
                    <a href="{b.url}" target="_blank" class="company-name">{b.company_name}</a>
                    {industry}
                </div>
                <div class="breach-details">
                    <span class="detail"><span class="label">Attacker:</span> {b.ransomware_group}</span>
                    <span class="detail"><span class="label">Location:</span> {b.location}</span>
                </div>
                {desc_html}
            </div>
'''
        
        date_blocks += f'''
        <div class="date-group">
            <h3 class="date-header">{date}</h3>
            <div class="breach-list">
                {item_rows}
            </div>
        </div>
'''
    
    # Stats
    total = len(breaches)
    healthcare = len([b for b in breaches if "🏥" in (b.industry or "")])
    financial = len([b for b in breaches if "🏦" in (b.industry or "")])
    
    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚨 Data Breach Alerts</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #e4e4e7;
            padding: 40px 20px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        
        header {{
            text-align: center;
            margin-bottom: 40px;
        }}
        h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #ff6b6b, #ffa502);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .subtitle {{
            color: #9ca3af;
            font-size: 1rem;
        }}
        
        .stats {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-bottom: 40px;
            flex-wrap: wrap;
        }}
        .stat {{
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 15px 25px;
            text-align: center;
        }}
        .stat-value {{ font-size: 1.8rem; font-weight: bold; color: #fff; }}
        .stat-label {{ font-size: 0.85rem; color: #9ca3af; }}
        
        .date-group {{
            margin-bottom: 35px;
        }}
        .date-header {{
            font-size: 1.1rem;
            color: #9ca3af;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        
        .breach-list {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        
        .breach-card {{
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 12px;
            padding: 18px 20px;
            transition: all 0.2s ease;
        }}
        .breach-card:hover {{
            background: rgba(255,255,255,0.06);
            border-color: rgba(255,255,255,0.15);
            transform: translateX(4px);
        }}
        
        .breach-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }}
        .company-name {{
            font-size: 1.2rem;
            font-weight: 600;
            color: #fff;
            text-decoration: none;
        }}
        .company-name:hover {{
            color: #60a5fa;
            text-decoration: underline;
        }}
        
        .badge {{
            font-size: 0.75rem;
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 500;
        }}
        .badge-default {{ background: rgba(255,255,255,0.1); color: #9ca3af; }}
        .badge-health {{ background: rgba(239,68,68,0.2); color: #fca5a5; }}
        .badge-financial {{ background: rgba(59,130,246,0.2); color: #93c5fd; }}
        .badge-gov {{ background: rgba(168,85,247,0.2); color: #d8b4fe; }}
        
        .breach-details {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            font-size: 0.9rem;
        }}
        .detail {{ color: #9ca3af; }}
        .detail .label {{ color: #6b7280; }}
        
        .company-desc {{
            margin-top: 10px;
            font-size: 0.85rem;
            color: #6b7280;
            font-style: italic;
        }}
        
        footer {{
            text-align: center;
            margin-top: 50px;
            color: #4b5563;
            font-size: 0.85rem;
        }}
        footer a {{ color: #60a5fa; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🚨 Data Breach Alerts</h1>
            <p class="subtitle">Automated monitoring of ransomware attacks & data breaches</p>
        </header>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{total}</div>
                <div class="stat-label">Breaches Found</div>
            </div>
            <div class="stat">
                <div class="stat-value">{healthcare}</div>
                <div class="stat-label">🏥 Healthcare</div>
            </div>
            <div class="stat">
                <div class="stat-value">{financial}</div>
                <div class="stat-label">🏦 Financial</div>
            </div>
        </div>
        
        {date_blocks}
        
        <footer>
            <p>Sources: ransomware.live | Updated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
            <p><a href="https://www.ransomware.live" target="_blank">View Source</a></p>
        </footer>
    </div>
</body>
</html>'''
    return html


def main():
    print(f"[*] Running breach monitor - {datetime.now()}")
    
    breaches = get_ransomware_live_victims(days_back=7)
    
    # Save HTML
    html = generate_html_view(breaches)
    with open(HTML_PATH, 'w') as f:
        f.write(html)
    
    # Save simple JSON
    feed = {
        "generated_at": datetime.now().isoformat(),
        "total_breaches": len(breaches),
        "breaches": [
            {
                "company": b.company_name,
                "date": b.attack_date,
                "attacker": b.ransomware_group,
                "location": b.location,
                "industry": b.industry,
                "url": b.url
            }
            for b in breaches
        ]
    }
    with open(JSON_PATH, 'w') as f:
        json.dump(feed, f, indent=2)
    
    print(f"\n[*] Found {len(breaches)} breaches")
    print(f"[*] Saved to: {HTML_PATH}")
    print(f"[*] Saved to: {JSON_PATH}")


if __name__ == "__main__":
    main()
