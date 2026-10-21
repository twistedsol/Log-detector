# Realone Log Detector

A small, readable detector that scans AWS CloudTrail-style audit logs and flags suspicious activity. Standard library only, no cloud account needed.

## What it does

It reads AWS CloudTrail-style audit logs and flags seven kinds of suspicious activity: root logins, logins without MFA, brute-force attempts (and a successful login right after them), risky IAM changes, buckets opened to everyone, and anyone switching off logging. It is pure Python with no extra packages, and it runs on the sample logs, so no cloud account is needed.

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

## Choices to avoid false alarms

- `NO_MFA_LOGIN` only checks IAM users, because federated and SSO logins don't report MFA the same way.
- A bucket policy open to everyone is not flagged if it has a `Condition` attached, such as being limited to one VPC endpoint.
- A single failed login is normal and is ignored. It takes three or more from one IP in a short time to count as brute force.

## Test it

```bash
python3 -m unittest -v
```

19 tests cover each rule, the clean cases above, unordered input and exit codes.

## Sample data

`sample_logs.json` has 18 events, including one simulated attack. A stranger fails to log in four times from one IP, then gets in, creates an access key, gives another user admin rights, opens a bucket to the whole internet, and finally turns off logging. The detector reports 9 findings in time order, with severity levels.

Documentation-range IPs (RFC 5737) and the example account ID `123456789012` are used throughout.

## How I built it

This is part of a 30-day challenge to learn cloud security by building in public. I wrote the code together with Claude, vibe coding to learn how to build better projects next time.

## One thing that went wrong

When I first ran the tests, one failed. The test said the sample file should contain 19 events, but it has 18. The detector was right and the test was wrong. The lesson: when a test fails, check whether the code or the test is at fault before changing anything.

## What I learned

- A rule that fires too easily is almost as bad as one that never fires, so I wrote down the choices I made to avoid false alarms.
- When a test fails, the test can be the thing that is wrong. I check both before changing anything.
- Automatic tests on GitHub run every time I push, so I find mistakes early.
- Vibe coding works best when I run the code and read what it does, not just accept it.

## Limits

It has only been run on sample data, not real production logs. The rules are simple thresholds, and it only understands AWS-style logs.

## Next ideas

- Point it at real CloudTrail logs from a free-tier account (the AWS lab, later)
- Add a rule for logins from a new country or IP range
- Output a markdown incident report
