# POP Configuration Guide

POP uses a YAML configuration file. Below is a complete example with explanations for each field.

## Example Configuration

```yaml
log:
  file: "/var/log/pop.log"    # Path to log file
  verbose: false               # Enable verbose logging
  debug: false                 # Enable debug logging

services:
  rpz:
    zonename: "rpz.example.com."   # RPZ zone name
    serialcache: "/var/cache/pop/serial.cache"  # Path to serial cache file
  reaper:
    interval: 3600   # Cleanup interval in seconds

apiserver:
  active: true
  name: "pop-api"
  key: "your-api-key"
  addresses:                   # HTTP listen addresses
    - "127.0.0.1:8080"
  tlsaddresses:                # HTTPS listen addresses
    - "0.0.0.0:8443"

dnsengine:
  active: true
  name: "pop-dns"
  addresses:
    - "127.0.0.1:53"
  logfile: "/var/log/pop-dns.log"

bootstrapserver:
  active: false
  name: "pop-bootstrap"
  addresses:
    - "127.0.0.1:9090"
  tlsaddresses:
    - "0.0.0.0:9443"
  logfile: "/var/log/pop-bootstrap.log"

keystore:
  path: "/etc/pop/keystore.json"   # Path to keystore file (must exist)

sources:
  example-mqtt-source:
    active: true
    name: "example-mqtt-source"
    description: "Example MQTT intelligence source"
    type: "mqtt"              # Source type: mqtt, file, etc.
    format: "json"            # Data format
    source: "mqtt://broker.example.com"
    topic: "tapir/feed/blocklist"
    validatorkey: "path/to/validator.key"
    bootstrap:
      - "https://bootstrap.example.com/feed"
    bootstrapurl: "https://bootstrap.example.com"
    bootstrapkey: "path/to/bootstrap.key"

  example-file-source:
    active: true
    name: "example-file-source"
    description: "Example local file source"
    type: "file"
    format: "rpz"
    source: "local"
    filename: "/etc/pop/blocklist.rpz"
    immutable: false          # If true, source will not be updated

policy:
  logfile: "/var/log/pop-policy.log"
  allowlist:
    action: "accept"          # Action for allowlisted domains: accept
  denylist:
    action: "drop"            # Action for denylisted domains: drop
  doubtlist:
    numsources:
      limit: 3                # Block if seen in this many sources
      action: "drop"
    numtapirtags:
      limit: 2                # Block if has this many TAPIR tags
      action: "drop"
    denytapir:
      tags:                   # Block if domain has any of these tags
        - "malware"
        - "phishing"
      action: "drop"
```

## Required Fields

All fields marked below are required unless stated otherwise.

| Section | Field | Required | Description |
|---------|-------|----------|-------------|
| log | file | ✅ | Log file path |
| log | verbose | ✅ | Verbose logging toggle |
| log | debug | ✅ | Debug logging toggle |
| services.rpz | zonename | ✅ | RPZ zone name |
| services.rpz | serialcache | ✅ | Serial cache file path |
| services.reaper | interval | ✅ | Reaper interval in seconds |
| apiserver | active | ✅ | Enable API server |
| apiserver | name | ✅ | API server name |
| apiserver | key | ✅ | API authentication key |
| apiserver | addresses | ✅ | HTTP listen addresses |
| apiserver | tlsaddresses | ✅ | HTTPS listen addresses |
| dnsengine | active | ✅ | Enable DNS engine |
| dnsengine | name | ✅ | DNS engine name |
| dnsengine | addresses | ✅ | DNS listen addresses |
| dnsengine | logfile | ✅ | DNS engine log file |
| keystore | path | ✅ | Path to keystore file (must exist) |
| sources.* | active | ✅ | Enable this source |
| sources.* | name | ✅ | Source name |
| sources.* | description | ✅ | Source description |
| sources.* | type | ✅ | Source type (mqtt, file, etc.) |
| sources.* | format | ✅ | Data format (json, rpz, etc.) |
| sources.* | source | ✅ | Source connection string |
| policy.allowlist | action | ✅ | Action for allowlisted domains |
| policy.denylist | action | ✅ | Action for denylisted domains |