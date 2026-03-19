#!/usr/bin/env python3
"""
Breach Monitor - Dashboard UI with filtering & navigation
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
    company_description: str
    industry: str


def search_company_info(company_name: str) -> dict:
    info = {"description": "", "industry": ""}
    name_lower = company_name.lower()
    
    industry_patterns = {
        "Healthcare": ["hospital", "health", "medical", "clinic", "pharma", "pharmacy", "dental", "care", "clinical"],
        "Financial": ["bank", "financial", "insurance", "credit", "capital", "investment", "trust"],
        "Technology": ["tech", "software", "systems", "digital", "data", "cloud", "cyber"],
        "Government": ["government", "municipal", "city", "county", "state", "federal", "court", "cad"],
        "Education": ["school", "university", "college", "academy"],
        "Manufacturing": ["manufacturing", "industrial", "metal", "steel", "chemical", "equipment"],
        "Retail": ["retail", "store", "shop", "market", "distribution"],
        "Transportation": ["transport", "logistics", "shipping", "trucking", "airline", "aviation"],
        "Energy": ["energy", "electric", "power", "gas", "oil", "solar"]
    }
    
    for industry, patterns in industry_patterns.items():
        if any(p in name_lower for p in patterns):
            info["industry"] = industry
            break
    
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
        
        for link in soup.find_all('a', href=True):
            if '/id/' in link.get('href', ''):
                clean = link.get('href', '').split('#')[0]
                full_url = f"https://www.ransomware.live{clean}"
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
        
        print(f"    Found {len(seen_urls)} victims")
        
        for i, victim_url in enumerate(list(seen_urls)[:25]):
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
                location=details.get('location', 'Unknown'),
                victims=details.get('victims', '—'),
                data_at_risk="Data exfiltrated",
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


def generate_html_dashboard(breaches: list[BreachReport]) -> str:
    # Get unique values for filters
    industries = sorted(set(b.industry for b in breaches if b.industry))
    attackers = sorted(set(b.ransomware_group for b in breaches if b.ransomware_group != 'Unknown'))
    dates = sorted(set(b.attack_date for b in breaches), reverse=True)
    
    # Industry icon mapping
    industry_icons = {
        "Healthcare": "🏥",
        "Financial": "🏦", 
        "Technology": "💻",
        "Government": "🏛️",
        "Education": "🎓",
        "Manufacturing": "🏭",
        "Retail": "🏪",
        "Transportation": "✈️",
        "Energy": "⚡"
    }
    
    # Create filter options
    industry_options = "".join(f'<option value="{i}">{industry_icons.get(i, "")} {i}</option>' for i in industries)
    attacker_options = "".join(f'<option value="{a}">{a}</option>' for a in attackers)
    
    # Generate breach cards as JSON for client-side filtering
    breaches_json = json.dumps([
        {
            "company": b.company_name,
            "date": b.attack_date,
            "attacker": b.ransomware_group,
            "location": b.location,
            "industry": b.industry,
            "url": b.url,
            "desc": b.company_description[:100]
        }
        for b in breaches
    ])
    
    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚨 Breach Monitor</title>
    <style>
        :root {{
            --bg: #0f0f23;
            --card-bg: #1a1a2e;
            --border: #2a2a4a;
            --text: #e4e4e7;
            --text-dim: #9ca3af;
            --accent: #6366f1;
            --accent-hover: #818cf8;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }}
        
        .navbar {{
            background: var(--card-bg);
            border-bottom: 1px solid var(--border);
            padding: 15px 30px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        
        .logo {{
            font-size: 1.4rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .logo-icon {{
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #ef4444, #f59e0b);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }}
        
        .nav-stats {{
            display: flex;
            gap: 20px;
        }}
        
        .nav-stat {{
            text-align: center;
        }}
        
        .nav-stat-value {{
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--accent);
        }}
        
        .nav-stat-label {{
            font-size: 0.7rem;
            color: var(--text-dim);
            text-transform: uppercase;
        }}
        
        .main {{
            display: flex;
            min-height: calc(100vh - 70px);
        }}
        
        .sidebar {{
            width: 260px;
            background: var(--card-bg);
            border-right: 1px solid var(--border);
            padding: 20px;
            position: sticky;
            top: 70px;
            height: calc(100vh - 70px);
            overflow-y: auto;
        }}
        
        .filter-section {{
            margin-bottom: 25px;
        }}
        
        .filter-title {{
            font-size: 0.75rem;
            text-transform: uppercase;
            color: var(--text-dim);
            margin-bottom: 10px;
            letter-spacing: 0.5px;
        }}
        
        .filter-select {{
            width: 100%;
            padding: 10px 12px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 0.9rem;
            cursor: pointer;
        }}
        
        .filter-select:focus {{
            outline: none;
            border-color: var(--accent);
        }}
        
        .quick-filters {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        
        .quick-btn {{
            padding: 10px 12px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-dim);
            cursor: pointer;
            text-align: left;
            font-size: 0.85rem;
            transition: all 0.2s;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .quick-btn:hover, .quick-btn.active {{
            background: var(--accent);
            border-color: var(--accent);
            color: white;
        }}
        
        .quick-btn .count {{
            background: rgba(255,255,255,0.2);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.75rem;
        }}
        
        .content {{
            flex: 1;
            padding: 25px;
        }}
        
        .content-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }}
        
        .search-box {{
            display: flex;
            align-items: center;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 8px 15px;
            width: 300px;
        }}
        
        .search-box input {{
            background: transparent;
            border: none;
            color: var(--text);
            font-size: 0.9rem;
            width: 100%;
            margin-left: 10px;
        }}
        
        .search-box input:focus {{
            outline: none;
        }}
        
        .search-box input::placeholder {{
            color: var(--text-dim);
        }}
        
        .results-count {{
            color: var(--text-dim);
            font-size: 0.9rem;
        }}
        
        .breach-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 15px;
        }}
        
        .breach-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px;
            transition: all 0.2s;
            cursor: pointer;
        }}
        
        .breach-card:hover {{
            border-color: var(--accent);
            transform: translateY(-2px);
        }}
        
        .breach-card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }}
        
        .company-name {{
            font-weight: 600;
            font-size: 1rem;
            color: var(--text);
            text-decoration: none;
            word-break: break-word;
        }}
        
        .company-name:hover {{
            color: var(--accent);
        }}
        
        .industry-badge {{
            font-size: 0.7rem;
            padding: 4px 10px;
            border-radius: 20px;
            background: rgba(99, 102, 241, 0.2);
            color: var(--accent-hover);
            white-space: nowrap;
        }}
        
        .breach-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            font-size: 0.8rem;
            color: var(--text-dim);
        }}
        
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        
        .attacker-tag {{
            display: inline-block;
            padding: 3px 10px;
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border-radius: 4px;
            font-size: 0.75rem;
            margin-top: 10px;
        }}
        
        .date-badge {{
            font-size: 0.75rem;
            color: var(--text-dim);
        }}
        
        .no-results {{
            text-align: center;
            padding: 60px;
            color: var(--text-dim);
        }}
        
        .no-results-icon {{
            font-size: 3rem;
            margin-bottom: 15px;
        }}
        
        /* Scrollbar */
        ::-webkit-scrollbar {{
            width: 8px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: var(--bg);
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: var(--border);
            border-radius: 4px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: var(--accent);
        }}
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="logo">
            <div class="logo-icon">⚠️</div>
            <span>Breach Monitor</span>
        </div>
        <div class="nav-stats">
            <div class="nav-stat">
                <div class="nav-stat-value" id="totalCount">{len(breaches)}</div>
                <div class="nav-stat-label">Total</div>
            </div>
            <div class="nav-stat">
                <div class="nav-stat-value">{len(industries)}</div>
                <div class="nav-stat-label">Industries</div>
            </div>
            <div class="nav-stat">
                <div class="nav-stat-value">{len(attackers)}</div>
                <div class="nav-stat-label">Groups</div>
            </div>
        </div>
    </nav>
    
    <div class="main">
        <aside class="sidebar">
            <div class="filter-section">
                <div class="filter-title">🔍 Search</div>
                <div class="search-box">
                    <span>🔎</span>
                    <input type="text" id="searchInput" placeholder="Search companies...">
                </div>
            </div>
            
            <div class="filter-section">
                <div class="filter-title">🏭 Industry</div>
                <select class="filter-select" id="industryFilter">
                    <option value="">All Industries</option>
                    {industry_options}
                </select>
            </div>
            
            <div class="filter-section">
                <div class="filter-title">💀 Attacker Group</div>
                <select class="filter-select" id="attackerFilter">
                    <option value="">All Attackers</option>
                    {attacker_options}
                </select>
            </div>
            
            <div class="filter-section">
                <div class="filter-title">📅 Date</div>
                <select class="filter-select" id="dateFilter">
                    <option value="">All Dates</option>
                    {"".join(f'<option value="{d}">{d}</option>' for d in dates)}
                </select>
            </div>
            
            <div class="filter-section">
                <div class="filter-title">⚡ Quick Filters</div>
                <div class="quick-filters">
                    <button class="quick-btn" onclick="filterByIndustry('Healthcare')">
                        🏥 Healthcare <span class="count">{len([b for b in breaches if b.industry == 'Healthcare'])}</span>
                    </button>
                    <button class="quick-btn" onclick="filterByIndustry('Financial')">
                        🏦 Financial <span class="count">{len([b for b in breaches if b.industry == 'Financial'])}</span>
                    </button>
                    <button class="quick-btn" onclick="filterByIndustry('Technology')">
                        💻 Technology <span class="count">{len([b for b in breaches if b.industry == 'Technology'])}</span>
                    </button>
                    <button class="quick-btn" onclick="filterByIndustry('Government')">
                        🏛️ Government <span class="count">{len([b for b in breaches if b.industry == 'Government'])}</span>
                    </button>
                </div>
            </div>
            
            <div class="filter-section">
                <button class="quick-btn" onclick="clearFilters()" style="width:100%; justify-content:center;">
                    ✖️ Clear All Filters
                </button>
            </div>
        </aside>
        
        <main class="content">
            <div class="content-header">
                <div class="results-count">Showing <span id="showingCount">{len(breaches)}</span> breaches</div>
            </div>
            
            <div class="breach-grid" id="breachGrid">
                <!-- Cards rendered by JavaScript -->
            </div>
            
            <div class="no-results" id="noResults" style="display:none;">
                <div class="no-results-icon">🔍</div>
                <div>No breaches match your filters</div>
            </div>
        </main>
    </div>
    
    <script>
        const breaches = {breaches_json};
        
        const industryIcons = {json.dumps(industry_icons)};
        
        function renderBreaches(data) {{
            const grid = document.getElementById('breachGrid');
            const count = document.getElementById('showingCount');
            const noResults = document.getElementById('noResults');
            
            count.textContent = data.length;
            
            if (data.length === 0) {{
                grid.innerHTML = '';
                noResults.style.display = 'block';
                return;
            }}
            
            noResults.style.display = 'none';
            grid.innerHTML = data.map(b => `
                <div class="breach-card">
                    <div class="breach-card-header">
                        <a href="${{b.url}}" target="_blank" class="company-name">${{b.company}}</a>
                        ${{b.industry ? `<span class="industry-badge">${{industryIcons[b.industry] || ''}} ${{b.industry}}</span>` : ''}}
                    </div>
                    <div class="breach-meta">
                        <div class="meta-item">
                            <span>📅</span> ${{b.date}}
                        </div>
                        <div class="meta-item">
                            <span>📍</span> ${{b.location}}
                        </div>
                    </div>
                    ${{b.attacker !== 'Unknown' ? `<span class="attacker-tag">💀 ${{b.attacker}}</span>` : ''}}
                </div>
            `).join('');
        }}
        
        function filter() {{
            const search = document.getElementById('searchInput').value.toLowerCase();
            const industry = document.getElementById('industryFilter').value;
            const attacker = document.getElementById('attackerFilter').value;
            const date = document.getElementById('dateFilter').value;
            
            const filtered = breaches.filter(b => {{
                const matchSearch = !search || b.company.toLowerCase().includes(search) || b.attacker.toLowerCase().includes(search);
                const matchIndustry = !industry || b.industry === industry;
                const matchAttacker = !attacker || b.attacker === attacker;
                const matchDate = !date || b.date === date;
                return matchSearch && matchIndustry && matchAttacker && matchDate;
            }});
            
            renderBreaches(filtered);
        }}
        
        function filterByIndustry(ind) {{
            document.getElementById('industryFilter').value = ind;
            filter();
        }}
        
        function clearFilters() {{
            document.getElementById('searchInput').value = '';
            document.getElementById('industryFilter').value = '';
            document.getElementById('attackerFilter').value = '';
            document.getElementById('dateFilter').value = '';
            filter();
        }}
        
        document.getElementById('searchInput').addEventListener('input', filter);
        document.getElementById('industryFilter').addEventListener('change', filter);
        document.getElementById('attackerFilter').addEventListener('change', filter);
        document.getElementById('dateFilter').addEventListener('change', filter);
        
        // Initial render
        renderBreaches(breaches);
    </script>
</body>
</html>'''
    return html


def main():
    print(f"[*] Running breach monitor - {datetime.now()}")
    
    breaches = get_ransomware_live_victims(days_back=7)
    
    # Save HTML dashboard
    html = generate_html_dashboard(breaches)
    with open(HTML_PATH, 'w') as f:
        f.write(html)
    
    # Save JSON
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
    print(f"[*] Saved: {HTML_PATH}")
    print(f"[*] Saved: {JSON_PATH}")


if __name__ == "__main__":
    main()
