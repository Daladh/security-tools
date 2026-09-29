<p align="center">
  <img src="assets/logo.png" alt="DALADH — Cybersecurity & Intelligence" width="320">
</p>

# 🧰 security-tools

A small collection of **educational security utilities** written in Python. Each tool is self-contained, dependency-light and documented — built to practice both **software engineering** and **offensive security** fundamentals.

> ⚠️ **For authorized and educational use only.** Only run these tools against systems you own or have **explicit written permission** to test. Unauthorized scanning or access is illegal.

---

## Tools

| Tool | Description |
|------|-------------|
| [`port_scanner.py`](port_scanner.py) | Multithreaded TCP port scanner with banner grabbing |
| [`dir_fuzzer.py`](dir_fuzzer.py) | Directory / path discovery tool for web servers (wordlist-based) |
| [`jwt_inspector.py`](jwt_inspector.py) | Decode and inspect JSON Web Tokens; flags weak configurations |

---

## Requirements

- Python 3.8+
- Install dependencies:

  ```bash
  pip install -r requirements.txt
  ```

---

## Usage

### 🔍 Port scanner

Scan common ports (default) or a custom range, with a banner grab on open ports.

```bash
python port_scanner.py 127.0.0.1
python port_scanner.py 127.0.0.1 -p 1-1024 -t 200
```

### 📂 Directory fuzzer

Discover hidden paths on a web server using a wordlist.

```bash
python dir_fuzzer.py http://localhost:3000 -w wordlist.txt
python dir_fuzzer.py http://localhost:3000 -w wordlist.txt -x 200,301,302
```

### 🔑 JWT inspector

Decode a JWT and report on its header, payload and potential weaknesses (e.g. `alg: none`, missing expiry).

```bash
python jwt_inspector.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc
```

---

## Why these tools?

Each one re-implements a concept every web pentester relies on, from scratch, to show understanding rather than just tool usage:

- **Port scanning** — sockets, concurrency, timeouts.
- **Directory fuzzing** — HTTP handling, wordlists, status-code filtering.
- **JWT inspection** — base64url, token structure, common misconfigurations.

---

## License

Released under the [MIT License](LICENSE). Use responsibly.
