# 🛠 Tools

Security utilities for hardening, auditing, and defense.

## Available Tools

### [`server-hardening.sh`](server-hardening.sh)
Linux server hardening baseline script. Applies:
- System updates & automatic security patches
- SSH hardening (key-only, no root login)
- UFW firewall (deny all inbound except SSH)
- Fail2Ban for brute-force protection
- Kernel sysctl hardening (SYN flood, source routing, etc.)
- File permission lockdown
- Audit logging (auditd)

**Usage:**
```bash
# Preview changes without applying
sudo ./server-hardening.sh --dry-run

# Apply hardening
sudo ./server-hardening.sh
```

## Contributing

PRs welcome. Tools should be:
- **Defensive** — Helps defenders, not attackers
- **Documented** — Clear usage and what it does
- **Tested** — Note which distros/versions you tested on
- **Conservative** — Better to warn than to break
