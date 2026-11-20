# Don't Tell Proxy (starter demo)

A dark, responsive web-proxy landing page with a small Node/Express fetch proxy.

## Run locally

1. Install Node.js 18 or newer.
2. In this folder, run `npm install`.
3. Run `npm start`.
4. Visit `http://localhost:3000`.

## Important limitations

This is a starter/demo proxy, not a production-grade anonymous proxy or a full browser engine. Many sites will not work correctly because modern websites depend on JavaScript, cookies, complex redirects, and relative asset paths. Do not expose this demo publicly as-is. Before deployment, add authentication, strict destination allowlisting or robust DNS/IP pinning, rate limits, request/response size limits, abuse monitoring, and a hardened proxy implementation. The demo blocks common private/local destinations but that check alone is not a complete SSRF defense.
