## 📋 Changelog

### v2.0

#### Added
- Added adaptive filename guessing based on the server-side filename storage strategy.
- Added propagation of the detected filename mode from the MIME-type phase to the payload fuzzing phase.
- Added explicit filename modes:
  - `Original file name`
  - `Name in body`
  - `MD5`
  - `SHA1`
  - `TEST` fallback mode
- Added final aggregation of confirmed RCE findings before printing results.

#### Changed
- MIME-type scanning is now a required phase.
- Removed the optional MIME-skip workflow: MIME-type discovery is now used to infer how the server stores uploaded files before payload fuzzing starts.
- Improved `guessing_file_name()` so it generates candidates according to the detected mode instead of always testing every possible filename pattern.
- Improved upload-directory probing by reusing the detected filename strategy during payload testing.

#### Efficiency
- Once the filename strategy is detected, lookup attempts can be reduced from 3-4 candidate names to 1 candidate name per accepted upload.
- This can reduce unnecessary upload-directory GET requests up to 75%.
- Example: with 11 accepted payloads, lookup requests can drop from 33-44 requests to 11 requests.

#### Notes
- If the MIME-type phase cannot identify a valid filename strategy, upload-directory probing is skipped to avoid low-confidence and likely useless lookup attempts.

---

### v1.1
- Added MIME-type fuzzing with real magic bytes (JPEG, GIF, PNG, WebP, SVG, BMP, ICO, PDF)
- Added `--skip-mimetype` flag to skip MIME scan
- Improved baseline comparison using valid PNG
- Fixed URL construction using `urljoin`