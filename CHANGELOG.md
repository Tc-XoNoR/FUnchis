## 📋 Changelog

### v1.1
- Added MIME-type fuzzing with real magic bytes (JPEG, GIF, PNG, WebP, SVG, BMP, ICO, PDF)
- Added `--skip-mimetype` flag to skip MIME scan
- Improved baseline comparison using valid PNG
- Fixed URL construction using `urljoin`