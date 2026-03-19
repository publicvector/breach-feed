# Breach Monitor - Setup Guide

## Quick Start

### 1. Get Your Webhook URL (For Channel Messages)
If you just want simple Teams channel messages, create an Incoming Webhook:
1. Go to Teams channel > ... > Manage channel > Connectors
2. Find "Incoming Webhook" > Configure
3. Name it "Breach Alerts" > Create
4. Copy the webhook URL
5. Run: `export TEAMS_WEBHOOK_URL="https://..."`

### 2. For Planner Tasks (This Script)

You need an Azure AD App Registration with Planner permissions.

#### Step 1: Register App in Azure AD
1. Go to https://portal.azure.com
2. Search "App registrations" > New registration
3. Name: "Breach Monitor"
4. Supported account types: "Accounts in this organizational directory only"
5. Register > Copy **Application (client) ID** and **Directory (tenant) ID**

#### Step 2: Create Client Secret
1. Go to "Certificates & secrets"
2. New client secret > Description: "Breach Monitor" > Add
3. Copy the **secret value** (not the ID)

#### Step 3: Grant Planner Permissions
1. Go to "API permissions"
2. Add permission > Microsoft Graph > Application permissions
3. Select: **Tasks.ReadWrite** and **Group.ReadWrite.All**
4. Click "Grant admin consent" (or you'll need admin approval)

#### Step 4: Get Your Planner Plan ID
1. Open Teams > Go to your Planner plan
2. The Plan ID is in the URL: `https://tasks.office.com/.../planview?planId=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
3. Or use Graph Explorer: `GET https://graph.microsoft.com/v1.0/me/planner/tasks`

#### Step 5: Run the Script
```bash
export TENANT_ID="your-tenant-id"
export CLIENT_ID="your-client-id" 
export CLIENT_SECRET="your-client-secret"
export PLANNER_ID="your-plan-id"

python3 breach_monitor.py
```

#### Step 6: Set Up Daily Cron
```bash
crontab -e
# Add:
0 8 * * * cd ~/breach-monitor && \
  TENANT_ID="xxx" CLIENT_ID="xxx" CLIENT_SECRET="xxx" PLANNER_ID="xxx" \
  python3 breach_monitor.py >> breach.log 2>&1
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TENANT_ID` | Azure AD tenant ID |
| `CLIENT_ID` | Azure app client ID |
| `CLIENT_SECRET` | Azure app client secret |
| `PLANNER_ID` | The Planner plan ID to add tasks to |
| `TEAMS_WEBHOOK_URL` | (Optional) Teams webhook for channel messages |

## Data Sources

- **ransomware.live** - Tracks ransomware victims (free, no API key)
- Filters: 10,000+ victims OR sensitive data (SSN, health info, etc.)
