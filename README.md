# Have-I-Been-Pwned-Password-CLI

CLI that checks passwords against the Have I Been Pwned breach corpus using the k-anonymity API, so the plain-text password never leaves your machine.

### How It Works

1. The tool computes SHA-1 of the password locally.
2. Only the first 5 hex characters of that hash are sent to `api.pwnedpasswords.com/range/{prefix}` (k-anonymity model).
3. HIBP returns every hash suffix that starts with the prefix along with the number of times it was seen in breaches.
4. The CLI scans that list for the remaining 35 characters of your hash.
5. If a match is found the breach count is reported; otherwise the password is marked safe. The `Add-Padding` request header masks the exact response size from network observers.

## Setup

### Requirements

- Go 1.21 or newer
- `github.com/fatih/color`
- Internet access to `api.pwnedpasswords.com`

### Installation

```bash
git clone https://github.com/fantasywastaken/Have-I-Been-Pwned-Password-CLI.git
cd Have-I-Been-Pwned-Password-CLI
go mod tidy
go build -o hibp .
```

### Usage

```bash
hibp check hunter2
hibp check "correct horse battery staple"
hibp file passwords.txt
hibp file passwords.txt --delay 250ms --timeout 5s
```

Sub-commands:

| Command                | Purpose                                              |
| ---------------------- | ---------------------------------------------------- |
| `check <password>`     | Check a single password                              |
| `file <path>`          | Check every non-empty line in a file                 |
| `help` / `--help`      | Show usage                                           |

Flags (per sub-command):

| Flag         | Default   | Purpose                                    |
| ------------ | --------- | ------------------------------------------ |
| `--timeout`  | `10s`     | HTTP timeout per request                   |
| `--delay`    | `150ms`   | Delay between requests (`file` only)       |

Exit codes:

| Code | Meaning                                        |
| ---- | ---------------------------------------------- |
| `0`  | All checked passwords are safe                 |
| `1`  | At least one password was found in HIBP        |
| `2`  | At least one lookup failed                     |

### Features

- k-anonymity: only the first 5 chars of SHA-1 leave the machine.
- `Add-Padding: true` response padding to obscure hit vs. miss on the wire.
- Single-password and bulk-file modes with configurable rate limiting.
- Masked password display in output so shoulder-surfing risk stays low.
- Colored PWNED / SAFE / ERROR statuses via `fatih/color`.
- Bulk summary tally and exit codes suitable for CI or shell pipelines.
