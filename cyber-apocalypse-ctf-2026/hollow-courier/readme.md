---
name: Hollow Courier
type: Web App (Flask + caddy proxy + custom auth middleware)
difficulty: easy
---

# Hollow Courier write-up
**Goal:** Prevent spoofing attack against the application, on which guards are sending confidential information on private loopback connection.

## Architecture Overview
- three layers:
    1. **Perimeter proxy (Caddy)**
        - Edge reverse proxy.
        - Adds headers (X-Real-IP, X-Forwarded-Proto).
        - Trusted perimeter for the internal app (Trust boundary).

    2. **Authentication middleware (`gate.py`)**
        - Layered in front of the Flask app.
        - Checks the IP from which the request appears to come.
        - Trusts **all RFC-specified private IP ranges** by default.
        - Weak trust boundary implementation - leads to **CWE-290: Authentication Bypass by Spoofing**.
    3. **Flask application (`__init__.py`)**
        - Configures the app and WSGI middleware.
        - Uses ProxyFix for handling headers forwarded by proxies.
        - Defines maximum trusted hops for headers (like `X-Forwarded-For`).

## Vulnerability analysis
### 1. Overly permissive IP Trust in `gate.py`
`gate.py` checks the client IP but implicitly trusts any IP in the standard private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.). This approach is problematic:

- An attacker can spoof `X-Forwarded-For` / related headers to appear as if the request was originated from within the trusted private IP range.
- The middleware then treats the request as internal/trusted, enabling **authentication bypass**.

This directly matches **CWE-290**: authentication bypass by spoofing IP-related data or headers.

**Root cause:** The trust boundary for internal IPs is too wide - assumes ll private ranges are safe instead of restricting to the specific path the guard sends traffic over.

**Mitigation:** Narrow the trusted IP range in `gate.py` to only the specific loopback / internal subnet used between the perimeter and the guard. Avoid using all RFC private ranges.

### 2. Incorrect `ProxyFix` Configuration in `__init__.py`
The `__init__.py` configures `ProxyFix` as follows:
```python
# Deployment expects an edge cache and the application perimeter.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1)
```

Where:
- `x_for=2` specifies, that two hops in the `X-Forwarded-For` chain should be trusted by Flask.
- The wrong assumption here is: "Edge cache + application perimeter" = 2 trusted hops

**Root cause:** The cache layer is according to the assumption considered as a trusted source of security-related headers. Only the perimeter proxy (Caddy) should be trusted.
- By trusting 2 hops, app implicitly allows an intermediate layer, which can be abused by the attacker who injects headers before the cache. This influence the effective client IP and other forwareded values.

**Mitigation:** Adjust `ProxyFix` to trust only the perimeter:
```python
# The forwarded-for header should be securely set by the perimeter: x_for=1
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```
- This approach ensures that the Flask uses the last hop (Caddy) as trusted for `X-Forwarded-For`, which tightens the trust boundary.

### Resolution
Fixing these two issues mitigates risk of spoofing and authentication bypassing. By implemening these fixes, the automated code review by the CTF framework bot passes and we are able to retrieve a flag: `HTB{thr33_kn0ck5_0n_s34led_g4t3s_90925277c209d21586be158b3a3c9328}`

## Key Takeaways
- **Overly broad IP-based trust boundary is dangerous:**
    - Trusting all RFC private ranges in `gate.py` enables authentication bypass via header spoofing (CWE‑290).
    - The trust boundary should be narrowed to the exact internal path (e.g. loopback or a specific subnet) between perimeter and guard. Ideally, the narrowest possible applying least privilege principle.
- **ProxyFix must reflect the real, secure trust model:**
    - Setting `x_for=2` assumed the cache was a trusted hop, which is a wrong security assumption.
    - Only the perimeter proxy (Caddy) should be trusted for security-related headers.
- **Defense in depth for forwarded headers:**
    - Combine strict IP allowlists in middleware with minimal, correctly configured `ProxyFix`.
    - Ensure only the ege proxy is allowed to set or override headers like `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto`.
- Challenge highlights how a small misconfig in trust boundaries and proxy handling can be used to create a full authentication bypass attack chain.




