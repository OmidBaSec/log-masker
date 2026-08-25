# Sample logs

Synthetic logs for trying Log Masker without touching anything real. Every
address, hostname, account and key here is fabricated or reserved for
documentation (RFC 5737 / RFC 3849 ranges, `example`/`acme` names, AWS's own
`EXAMPLE` key ids).

| File | Scenario | Try it with |
|---|---|---|
| `ssh-brute-force.log` | Password spraying against a bastion, then a success and a sudo to root | Brute force / password spraying |
| `windows-lateral-movement.csv` | 4624/4648/7045 chain from a workstation to a file server and a DB | Lateral movement |
| `cloud-exfiltration.jsonl` | CloudTrail: bulk `GetObject`, bucket opened to the world, new access key | Exfiltration |

Paste one into the workspace and press **Preview masking** — no API key needed,
nothing leaves the machine. Then compare the *Masked data* tab with the original
to see exactly what would have been sent.

**Never add a real log here.** See [CONTRIBUTING.md](../CONTRIBUTING.md).
