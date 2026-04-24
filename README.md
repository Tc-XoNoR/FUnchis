# FUnchis

> File Upload Vulnerability Scanner

FUnchis is a Python tool designed to test file upload functionalities and identify weaknesses such as **filter bypass**, weak server-side validation, unsafe filename handling, and potential **remote code execution (RCE)** through malicious uploads.

> ⚠️ This project is under active development and currently focuses on PHP-based web applications.

---

## 🚀 Features

- Automatic upload form discovery through HTML parsing
- Baseline request generation using a valid PNG file
- MIME-type fuzzing using real minimal file contents / magic bytes:
  - JPEG, GIF, PNG, WebP, SVG, BMP, ICO, PDF
- Extension fuzzing for potentially dangerous PHP-related extensions:
  - `.php`, `.php2`, `.php3`, `.php4`, `.php5`, `.php6`, `.php7`, `.phps`, `.pht`, `.phtml`, `.phar`
- Response analysis based on status code, redirect behavior, cleaned HTML diff, and deny-keyword heuristics
- Adaptive filename guessing for uploaded files
- Optional upload directory probing with RCE marker detection
- Support for cookies, proxy usage, CSRF token refresh, and verbose output

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

- `--cookies` → cookies to include in the session, for example `"PHPSESSID=xxx, TOKEN=yyy"`
- `-x, --proxy` → proxy address, for example `127.0.0.1:8080`
- `--csrf` → refresh CSRF token before each request
- `-u, --upload` → upload directory to probe, for example `/uploads/`
- `-v, --verbose` → enable verbose output

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

---

## 🔮 Roadmap

- [x] Content-Type fuzzing and MIME validation bypass
- [X] Improve detection of server-side file renaming logic and response analysis
- [ ] Extend support to other backends
- [ ] Advanced filename-based attack techniques:
  - Injection via filename (e.g. SQL injection, command injection)
- [ ] Advanced extension bypass techniques:
  - Double extensions (`shell.php.png`, `shell.png.php`)
  - Uncommon extensions and parsing inconsistencies
- [ ] Aggressive mode:
  - Automated filter evasion techniques
  - Edge-case parsing behavior (e.g. quotes, null bytes, separators)

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
