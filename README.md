# Web Exposure Checker

## Publish on GitHub Pages
1. Create a repository and upload `index.html`, `style.css`, `app.js` (and optionally `worker.js`).
2. Settings → Pages → Source: "Deploy from a branch" → `main` / root → Save.
3. Open `https://<user>.github.io/<repo>/`.

## What the browser can and cannot prove
| Check | Browser only | With backend (`worker.js`) |
|---|---|---|
| Port 443 | `YES` if an HTTPS response arrives (TCP + valid TLS). Otherwise `UNKNOWN` (refused, TLS error, DNS, timeout and block look identical to a browser). | `YES` on TCP connect; `NO` only on explicit refusal; else `UNKNOWN` |
| Port 80 | `UNKNOWN` on GitHub Pages (https page cannot request http://, mixed content). Works only if the page is served over http. | same as above |
| Web Interface | `YES` if an HTTP response arrives (content is opaque to the browser). Otherwise `UNKNOWN`. | `YES` if HTML is returned; `NO` only if both ports are refused |

Browser-only mode never returns `NO`. Results reflect the network of whoever runs the scan.

## Optional backend
Deploy `worker.js` on Cloudflare Workers, set `ALLOWED_ORIGIN`, then set `BACKEND_URL` in `app.js`.
Limits: Workers cannot connect to Cloudflare-proxied hosts, private ranges, or fetch IPs directly (those return `UNKNOWN`).
