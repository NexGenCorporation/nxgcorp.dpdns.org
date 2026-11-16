# Secure website updates setup

The public site is hosted on GitHub Pages, which cannot read GitHub Secrets or securely persist edits from a browser. `updates.html` talks to a server-side Cloudflare Worker; it never includes or stores the admin password. `worker/updates.js` expects to be deployed on the same origin at `/api/updates` and a Cloudflare KV binding named `UPDATES`.

## Before deployment

The password previously pasted in chat is compromised and only eight digits long. **Do not configure that value as `ADMIN_PASS`.** Rotate it and choose a long, unique random password (at least 32 random characters). Set it directly as a Cloudflare Worker secret, and create a different random secret for `SESSION_SECRET` (at least 32 random characters). Never put either value in this repository or frontend code.

## Cloudflare configuration

1. Create a KV namespace and bind it to the Worker as `UPDATES`.
2. Deploy `worker/updates.js` as a Worker and route `https://<your-site-host>/api/updates*` to it. Serve the HTML and API on the same host so the secure, HttpOnly cookie works without cross-origin credential configuration.
3. Set Worker secrets `ADMIN_PASS` and `SESSION_SECRET` using Cloudflare's secret settings/CLI. Do not use GitHub Pages secrets for browser-side authentication.
4. Visit `/updates.html`; sign in to create, edit, and delete updates. Public pages can fetch `GET /api/updates`; records include creation/update timestamps.

The repository currently uses GitHub Pages and does not include Cloudflare Worker routing or deployment configuration. Until the Worker, KV binding, DNS route, and secrets are configured, the admin/API will remain unavailable. This worker provides basic per-IP login throttling; for a high-traffic or higher-risk deployment, use Cloudflare rate limiting/WAF as an additional control and monitor login failures.
