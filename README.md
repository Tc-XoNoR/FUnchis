# FUnchis

> File Upload Vulnerability Scanner

FUnchis is a Python tool designed to test file upload functionalities and identify weaknesses such as **filter bypass** and potential **remote code execution (RCE)** through malicious uploads.

> ⚠️ This project is under active development and currently focuses on PHP-based web applications.

---

## 🚀 Features

- Automatic upload form discovery (HTML parsing)
- Extension fuzzing:
  - `.php`, `.phtml`, `.phar`, `.pht`, etc.
- Response analysis:
  - Status code
  - Redirect behavior
  - Cleaned HTML diff
- Detection of:
  - Heuristic filtering via keyword matching and response diffing
  - Weak server-side validation logic
- File name guessing:
  - Extracted from responses
  - MD5 / SHA1 patterns
- Optional upload directory probing
- Support for:
  - Cookies
  - Proxy (Burp/ZAP)
  - CSRF token handling
- Verbose logging (`-v`)

---

## 🧠 How It Works

- Extracts upload form parameters
- Sends a valid request (PNG) as baseline
- Uploads a polyglot payload (PNG + PHP)
- Compares responses to detect filters
- Identifies allowed extensions
- Attempts file access and execution

---

## 📦 Installation

```bash
pip install requests beautifulsoup4
```

---

## 🛠️ Usage

```bash
python3 Funchis.py <URL> [OPTIONS]
```

### Options

- `--cookies` → `"PHPSESSID=xxx, TOKEN=yyy"`
- `-x, --proxy` → `127.0.0.1:8080`
- `--csrf` → refresh CSRF token per request
- `-u, --upload` → upload directory (e.g. `/uploads/`)
- `-v` → verbose 

---

## 📌 Examples

```bash
python3 Funchis.py http://target.com/upload.php
```

```bash
python3 Funchis.py http://target.com \
  --cookies "PHPSESSID=abcd1234" \
  -x 127.0.0.1:8080 \
  --csrf \
  --upload files/ \
  -v  
```

---

## ⚠️ Limitations

- Designed for HTML-based upload forms (no JS handling)
- Heuristic-based detection (may produce false positives/negatives)
- Focused on PHP-based applications
- Advanced bypass techniques not yet implemented
- Fuzzing mechanism can be improved

---

## 🔮 Roadmap

- [x] Content-Type fuzzing and MIME validation bypass

- [ ] Extend support to other backends

- [ ] Advanced filename-based attack techniques:
  - Injection via filename (e.g. SQL injection, command injection)

- [ ] Advanced extension bypass techniques:
  - Double extensions (`shell.php.png`, `shell.png.php`)
  - Uncommon extensions and parsing inconsistencies

- [ ] Aggressive mode:
  - Automated filter evasion techniques
  - Edge-case parsing behavior (e.g. quotes, null bytes, separators)

- [ ] Improve detection of server-side file renaming logic and response analysis

---

## 📋 Changelog

See [CHANGELOG.md](CHANGELOG.md)

---

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized testing only and may produce false positives or false negatives.

---

## 📄 License
MIT License — see [LICENSE](LICENSE) for details.

---

