# FUnchis

> File Upload Vulnerability Scanner

FUnchis is a Python tool designed to test file upload functionalities and identify weaknesses such as **filter bypass**, weak server-side validation, unsafe filename handling, and potential **remote code execution (RCE)** through malicious uploads.

> ⚠️ This project is under active development and currently focuses on PHP-based web applications.

---

## 🚀 Features

- Automatic upload form discovery through HTML parsing
- Baseline request generation using a valid file type selected with `--image-type`
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
- Sends a valid upload request as baseline
- Tests different MIME types using real minimal file contents
- Uploads PHP polyglot payloads
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

`--cookies` → cookies to include in the session, e.g. `"PHPSESSID=xxx, TOKEN=yyy"`  
`-x`, `--proxy` → proxy address, e.g. `127.0.0.1:8080`  
`--csrf` → refresh CSRF token before each request  
`-u`, `--upload` → upload directory to probe, e.g. `/uploads/`  
`--image-type` → valid file type used for the baseline upload test, default: `png`  
`-v`, `--verbose` → increase output verbosity  
`-A`, `--aggressive` → force FULL filename guessing (may generate many requests)  
`--bypass` → enable filename-based bypass techniques

---

## 📌 Examples

```bash
python3 Funchis.py http://target.com/upload.php
```

```bash
# Basic scan: detect allowed extensions and try file access in upload directory
python3 Funchis.py http://target.com/upload.php --upload uploads/ -v

# Advanced scan: authenticated context + proxy + CSRF handling + aggressive filename guessing + bypass techniques
python3 Funchis.py http://target.com --cookies "PHPSESSID=abcd1234" -x 127.0.0.1:8080 --csrf --upload files/ --image-type jpg -A --bypass -v
```

---

## ⚠️ Limitations

- Designed for HTML-based upload forms (no JS handling)
- Heuristic-based detection (may produce false positives/negatives)
- Focused on PHP-based applications

---

## 🔮 Roadmap

- [x] Content-Type fuzzing and MIME validation bypass
- [x] Improve detection of server-side file renaming logic and response analysis
- [x] Advanced extension bypass techniques:
  - Double extensions (`shell.php.png`, `shell.png.php`)
  - Uncommon extensions and parsing inconsistencies
- [x] Dynamic baseline file type selection with `--image-type`
- [ ] Extend support to other backends
- [ ] Advanced filename-based attack techniques:
  - Injection via filename (e.g. SQL injection, command injection)

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
