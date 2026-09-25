# Splunk Scheduled Alerts

Automated scheduled alerts configured for each detection rule.

*(Note: Splunk Free does not expose the Alert UI, so scheduled searches 
are configured directly via `savedsearches.conf`. This is functionally 
equivalent to native alerting.)*

| Alert Name | MITRE ID | Schedule | Next Run |
|---|---|---|---|
| T1136 - Account Creation Detection | T1136.001 | Every 5 min | 19:20 IST |
| T1110 - Brute Force Login Attempts | T1110 | Every 5 min | 19:20 IST |
| T1059.001 - Suspicious PowerShell | T1059.001 | Every 5 min | 19:20 IST |
| T1547.001 - Startup Folder Persistence | T1547.001 | Every 5 min | 19:20 IST |

## Configuration Method

Since Splunk Free does not support the Alert UI, these alerts are 
configured via the config file:

`/opt/splunk/etc/apps/search/local/savedsearches.conf`

Each entry uses:
- **cron_schedule:** `*/5 * * * *` (every 5 minutes)
- **dispatch.earliest_time:** `-5m`
- **enableSched:** `1`

## Screenshots

- Scheduled alerts: `../lab-setup/screenshots/16-scheduled-search.png`
- SOC dashboard: `../lab-setup/screenshots/17-soc-dashboard.png`
