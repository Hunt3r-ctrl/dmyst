<div align="center">

# 🌑 DARK MYSTERY

### Source Intelligence & Exposure Detection

**Uncover what hides in the source.**

A lightweight, rule-based scanner written in Go that identifies potential exposed credentials, API endpoints, sensitive routes, infrastructure references, and risky JavaScript patterns.

[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library-success)](https://pkg.go.dev/std)

</div>

## Overview

**DARK MYSTERY** is a command-line tool designed to inspect HTTP and HTTPS resources using configurable regular-expression rules.

It searches source content for patterns associated with potentially exposed credentials, application endpoints, third-party services, infrastructure references, and risky JavaScript constructs.

Built for security-focused workflows, DARK MYSTERY integrates into terminal pipelines, supports custom detection rules, and provides options to filter and save findings.

> **Identify the signal. Investigate the evidence. Verify the exposure.**

## Features

- **Embedded Detection Rules** — Built-in patterns compiled directly into the executable.
- **91 Detection Rules** — Rules covering multiple exposure and source-intelligence categories.
- **Custom Patterns** — Load additional detection rules using `-p` or `--patterns`.
- **Pipeline Integration** — Accept URL lists through standard input.
- **Result Export** — Save findings to a file using `-o` or `--output`.
- **Unique Findings** — Suppress duplicate findings using `-u` or `--unique`.
- **Quiet Mode** — Restrict accepted responses to HTTP 200 and prevent redirects from being followed.
- **Pattern Validation** — Validate detection rules using `--check-patterns`.
- **Version Information** — Display the tool version using `-v` or `--version`.
- **Lightweight Runtime** — Uses Go's standard library without third-party runtime dependencies.

## Installation

### Requirements

- Go 1.26.8 or a compatible Go toolchain that supports the version declared in `go.mod`.
- A supported operating system and architecture.
- Network access to authorized targets you intend to scan.

### Install using Go

Install the latest published version directly from the repository:

```bash
go install github.com/Hunt3r-ctrl/dmyst@latest
```

To install a specific version:

```bash
go install github.com/Hunt3r-ctrl/dmyst@v0.1.1
```

Go downloads the source and builds the executable automatically. No manual binary download is required.

After installation, ensure that Go's binary directory is included in your `PATH`.

The default installation directory is typically:

- Linux/macOS: `$(go env GOPATH)/bin`
- If `GOPATH` is unset, Go normally defaults to `$HOME/go`.

Verify the installation:

```bash
dmyst --version
dmyst --help
```

> Installation commands will work once the repository module path, published version tag, and required Go toolchain have been verified.

## Usage

DARK MYSTERY accepts URLs through standard input, one URL per line.

### Basic scan

```bash
cat js-urls.txt | dmyst
```

### Quiet mode with unique findings

```bash
cat js-urls.txt | dmyst -q -u
```

Quiet mode scans only HTTP 200 responses and silently ignores other HTTP statuses. It also prevents redirects from being followed.

### Save findings to a file

```bash
cat js-urls.txt | dmyst -o findings.txt
```

### Use custom detection patterns

```bash
cat js-urls.txt | dmyst -p custom-patterns.txt
```

### Validate embedded detection patterns

```bash
dmyst --check-patterns
```

### Display version information

```bash
dmyst --version
```

### Display help

```bash
dmyst --help
```

## Command-Line Options

| Option | Description |
|---|---|
| `-p`, `--patterns` | Load a custom detection pattern file |
| `-o`, `--output` | Save findings to a file |
| `-q`, `--quiet-errors` | Scan only HTTP 200 responses and silently ignore other statuses |
| `-u`, `--unique` | Suppress globally duplicate findings |
| `--check-patterns` | Validate patterns without scanning URLs |
| `-v`, `--version` | Display version information |
| `-h`, `--help` | Display usage information |

## Detection Intelligence

| Category | Detection Examples |
|---|---|
| Cloud & Infrastructure | AWS, Azure, Firebase, Cloudinary |
| Credentials & Tokens | API keys, tokens, JWTs, authorization patterns |
| Developer Platforms | GitHub, GitLab, npm, PyPI |
| Payments & Communications | Stripe, Twilio, SendGrid |
| API Discovery | GraphQL, REST, Swagger, OpenAPI |
| Sensitive Routes | Admin, internal, debug, health endpoints |
| Network References | Localhost, private IPs, WebSockets |
| JavaScript Patterns | `eval`, HTML injection sinks, `postMessage` |
| Configuration | CORS wildcards, debug settings, redirect parameters |

> Detection is pattern-based. Matches can produce false positives and do not independently establish that a secret is exposed or a vulnerability is exploitable.

## Proof of Concept (POC)
<img width="872" height="717" alt="dmyst-1" src="https://github.com/user-attachments/assets/28ac77b8-ec2a-4c78-86f2-a286f2924f3a" />



## Custom Detection Patterns

Each rule follows this format:

```text
Finding Name|RegularExpression
```

### Example `patterns.txt`

```text
# API discovery
GraphQL Endpoint|https?://[^"'\s]*(?:graphql|gql)[^"'\s]*

# Health endpoints
Health Endpoint|["'`]/(?:health|healthz|ready)["'`]

# Potential API key references
API Key Reference|api[_-]?key
```

### Pattern guidelines

- Separate the finding name and regular expression with `|`.
- Use one rule per line.
- Blank lines are ignored.
- Lines beginning with `#` are comments.
- Validate patterns before scanning.
- Use Go-compatible RE2 syntax; some Python and PCRE features are unsupported.

DARK MYSTERY converts some non-capturing group syntax during parsing. For reliable results, prefer regex expressions supported natively by Go's `regexp` package.

Validate the embedded patterns:

```bash
dmyst --check-patterns
```

Validate a custom pattern file:

```bash
dmyst --patterns custom-patterns.txt --check-patterns
```

## Workflow

```text
          URL INPUT
              |
              v
     +------------------+
     |   DARK MYSTERY   |
     +------------------+
              |
              v
     +------------------+
     | Detection Engine |
     |                  |
     | Embedded Rules   |
     | Custom Patterns  |
     +------------------+
              |
              v
     +------------------+
     | Matched Findings |
     +------------------+
              |
              v
      Terminal / File
```

## Project Structure

```text
dark-mystery/
├── main.go
├── patterns.txt
├── go.mod
├── README.md
└── .gitignore
```

## Technical Details

- Written in Go.
- Uses the Go standard library.
- Default detection patterns are embedded into the executable at build time.
- HTTP requests have a 15-second timeout.
- Response bodies are limited to 5 MiB per URL.
- Findings are matched against response content using compiled regular expressions.
- Output files are created with restrictive file permissions where supported.

## Limitations

- Pattern matches are indicators, not confirmed vulnerabilities.
- Some matches may be false positives, and some issues may not be detected.
- Unique mode suppresses duplicate output; the summary counts total matches separately.
- Responses exceeding the configured size limit are truncated.
- Quiet mode accepts only HTTP 200 responses and does not follow redirects.
- The scanner does not independently validate whether discovered credentials are active.
- A successful scan does not establish that a target is secure.

## Responsible Use

DARK MYSTERY is intended for authorized security testing, defensive auditing, and source-code analysis.

- Obtain authorization before scanning systems you do not own.
- Treat potential credentials, tokens, and sensitive findings as confidential.
- Never use discovered credentials without explicit authorization.
- Store reports securely and redact sensitive information before sharing.
- Verify findings manually before classifying them as security issues.
- Follow applicable laws, organizational policies, and responsible disclosure practices.

The tool provides detection signals to support investigation. It does not guarantee that every match is accurate or that a vulnerability is exploitable.

## Version

The source currently declares version `v0.1.1`.

Check the repository's Releases page for published versions.

## License

DARK MYSTERY is open-source software released under the MIT License.

Copyright (c) 2026 DARK MYSTERY contributors.

Permission is granted to use, copy, modify, distribute, sublicense, and sell copies of the tool, subject to the terms and conditions of the MIT License.

<div align="center">

**DARK MYSTERY**  
*Inspect carefully. Verify findings. Act responsibly.*

</div>
