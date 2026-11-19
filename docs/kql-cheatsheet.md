# KQL Quick Reference

The Kusto Query Language (KQL) operators used in this investigation, with the analyst question each one answers. KQL is the query language of Microsoft Sentinel, Defender XDR and Azure Data Explorer.

[← Back to the main README](../README.md)

| Operator | What it does | Example from this investigation |
|---|---|---|
| `take` / `limit` | Return a few rows, to explore a table | `DnsEvents \| take 5` |
| `project` | Keep only the columns you need | `\| project timestamp, src_ip, url` |
| `where ==` | Exact match | `\| where vlan == "dmz"` |
| `where contains` | Substring match, case-insensitive | `\| where sender contains "whiskersandwonders"` |
| `where has` | Whole-term match, faster than `contains` | `\| where resolved_ips has "185.174.137.42"` |
| `startswith` / `endswith` | Prefix / suffix match | `\| where ip_address startswith "10.10.1."` |
| `!endswith` | Negation, to find what *doesn't* match | `\| where sender !endswith "@whiskersandwonders.org"` |
| `in (...)` | Match against a list, useful for IOC lists | `\| where query_name in ("update-cdn-service.xyz")` |
| `between (.. )` | Time window | `\| where timestamp between (datetime(...) .. datetime(...))` |
| `distinct` | Unique values | `\| distinct client_ip` |
| `summarize count() by` | Group and count | `\| summarize count() by protocol` |
| `summarize min()/max()` | First and last seen | `\| summarize first_beacon = min(timestamp), last_beacon = max(timestamp) by client_ip` |
| `order by` | Sort | `\| order by count_ desc` |
| `join kind=inner` | Enrich one table with another | DNS evidence joined with `Employees` to get names and roles |
| `matches regex` | Pattern match, for behaviour-based detection | `\| where url matches regex @"/api/v\d+/(status\|config)"` |

## Pivoting pattern used in this case

```
Indicator (IP)  ──DnsEvents──►  Domain + affected hosts
Affected hosts  ──NetworkFlow─►  Port / protocol of the C2 channel
Domain          ──ProxyEvents─►  Beacon URLs and frequency
Hypothesis "phishing" ──Email──►  Lookalike sender, recipients
Recipients ⨝ affected hosts ───►  Confirmed attack chain
Host IPs   ⨝ Employees ────────►  Who, which role, business impact
```

## Network facts used in the analysis

| Port | Service | Notes |
|---|---|---|
| 22 | SSH | Remote shell |
| 25 | SMTP | Sending email; the busiest port in this network |
| 53 | DNS | Mostly UDP |
| 80 | HTTP | Unencrypted web |
| 443 | HTTPS | Encrypted web; abused for C2 because it's almost always allowed |
| 3389 | RDP | Windows remote desktop |

**Private IPv4 ranges (RFC 1918):** `10.0.0.0/8`, `172.16.0.0/12` (172.16 to 172.31), `192.168.0.0/16`. Everything else is public.

**HTTP status codes:** 200 OK · 301/302 Redirect · 403 Forbidden · 404 Not Found · 500 Server Error
**DNS record types:** A (IPv4) · AAAA (IPv6) · MX (mail server) · CNAME (alias) · TTL is how long a result may be cached
