# Realone Log Detector

A small, readable detector that scans AWS CloudTrail-style audit logs and flags suspicious activity. Standard library only, no cloud account needed.

## Run it

```bash
python3 detector.py sample_logs.json
```

More options:

```bash
python3 detector.py sample_logs.json --format json          # machine-readable output
python3 detector.py sample_logs.json --min-severity high    # hide low and medium findings
python3 detector.py logs/*.json.gz --threshold 5            # real CloudTrail files (gzip works)
```

The exit code is `1` when any finding is at or above `--fail-on` (default `high`), so it can gate a script or CI job.

## Rules

| Rule | Severity | Fires when |
|------|----------|------------|
| `ROOT_LOGIN` | high (medium if failed) | The root user signs in to the console |
| `NO_MFA_LOGIN` | medium | An IAM user signs in successfully without MFA |
| `BRUTE_FORCE` | high | 3+ failed console logins from one IP, each within 10 minutes of the last |
| `BRUTE_FORCE_SUCCESS` | critical | A login succeeds from that same IP right after a burst |
| `IAM_PRIVILEGE_CHANGE` | high / medium | AdministratorAccess attached (high), or other policy, user or access key changes (medium) |
| `PUBLIC_BUCKET` | high | A bucket policy or ACL opens a bucket to everyone, or its public access block is removed |
| `LOGGING_TAMPERED` | critical / high | `StopLogging` or `DeleteTrail` (critical), `UpdateTrail` or `PutEventSelectors` (high) |

## Avoiding false alarms

- `NO_MFA_LOGIN` only checks IAM users, because federated and SSO logins don't report MFA the same way.
- A wildcard bucket policy with a `Condition` (for example, limited to a VPC endpoint) is not flagged.
- A single failed login is normal and is not flagged.

## Test it

```bash
python3 -m unittest -v
```

19 tests cover each rule, the clean cases above, unordered input and exit codes.

## Sample data

`sample_logs.json` has 18 events, including one simulated attack: four failed logins, a successful login, a new access key, an admin policy attached, a bucket opened to the world, and logging switched off. Documentation-range IPs (RFC 5737) and the example account ID `123456789012` are used throughout.

## Next ideas

- Point it at real CloudTrail logs from a free-tier account (the AWS lab, later)
- Add a rule for logins from a new country or IP range
- Output a markdown incident report
