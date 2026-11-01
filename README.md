# Work apps launcher

Served at https://result6393.github.io/

To add or remove an app, edit the JSON list inside `index.html` (the `<script id="apps">` block). Each entry: `name`, `url`, `desc`, optional `note`.

Personal apps are deliberately not listed here.

## Settings sync (`settings/`, `worker/`)

Work apps sync their settings across devices through a Cloudflare Worker
(`worker/`, deployed as `work-settings` at https://work-settings.aflibercept.workers.dev).

- `settings/sync.js` is the shared client. Each app keeps an identical copy; update them together.
- Settings are encrypted in the browser with a key derived from the sync password; the Worker
  stores only ciphertext in KV and only the SHA-256 of the auth token (`AUTH_HASH` secret).
- `settings/setup.html` (https://result6393.github.io/settings/setup.html) generates `AUTH_HASH`.
- 10 wrong passwords from one IP locks that IP out for 15 minutes.
