## 📋 Changelog

## v2.3   -  2026-05-22 

- Fixed URL normalization to avoid appending trailing slashes to file-like targets such as `index.html` or `upload.php`.

---

### v2.2  -  2026-05-08

#### Added

- Added `--image-type` to choose the file type used for the valid upload test.

#### Changed

- Removed the hardcoded PNG baseline and added support for different file types.
- Payload and bypass tests now use the selected file type instead of always using PNG.
- Improved upload form parsing to support more input fields.
- Renamed default test files from `test.*` to `kyra.*`.

#### Fixed

- Fixed redirect detection when redirects are automatically followed.
- Fixed URL handling when the target URL contains query parameters.

---

### v2.1  -  2026-04-30

#### Added

- Added `--bypass` mode to test filename-based upload bypass techniques, including double extensions and extension parsing edge cases such as encoded characters, null byte patterns, separators and uncommon PHP extensions.
- Added `--aggressive` mode to force FULL filename guessing when broader lookup coverage is needed, even if a specific naming strategy was previously detected.

#### Changed

- Improved filename lookup reliability: failed checks no longer overwrite previously detected file naming strategies, preventing false `Guessing Filename failed` results.
- When multiple naming strategies are detected, FUnchis now falls back to FULL filename guessing to reduce the risk of missing uploaded files.

#### Fixed

- Fixed a filename guessing bug where a failed lookup in the last loop iteration could overwrite a previously valid detection result, causing FUnchis to incorrectly report `Guessing Filename failed` and skip the file lookup phase.
- Fixed filename lookup state handling by introducing a `FAILED` fallback result and updating the detected naming strategy only when a real stored filename is found.

---

### v2.0  -   2026-04-24

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

### v1.1  -   2026-04-17
- Added MIME-type fuzzing with real magic bytes (JPEG, GIF, PNG, WebP, SVG, BMP, ICO, PDF)
- Added `--skip-mimetype` flag to skip MIME scan
- Improved baseline comparison using valid PNG
- Fixed URL construction using `urljoin`