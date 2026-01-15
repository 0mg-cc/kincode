# KinCode

Shared TOTP-based identity verification for non-technical users.

Generate a common secret code that family members or trusted groups can use to verify each other's identity using standard authenticator apps.

![Screenshot](screenshot1.jpg)

## Features

- **Fully client-side**: no data sent to server, everything runs in the browser
- **Zero-knowledge**: server only serves static files, no compute or storage
- **TOTP standard**: compatible with Google Authenticator, Authy, 2FAS, FreeOTP
- **Accessible**: WCAG compliant, keyboard navigation, screen reader support
- **Multilingual**: French, English, Spanish (auto-detected or manual selection)
- **Privacy-focused**: no tracking, no cookies, no telemetry
- **No third-party requests**: system fonts only, no external CDNs
- **Pedagogical**: clear explanations and security warnings for non-technical users

## Use case

Enable low-tech identity verification between trusted individuals (grandparent/grandchild, family members, close friends) without requiring passwords, SMS, or centralized services.

**Important**: All participants must be physically present together when generating and scanning the QR codes. The secret must be established in person to maintain security.

Each person scans their QR code once, then all apps generate identical 6-digit codes every 30 seconds. Matching codes prove identity.

## Deployment

### Docker Compose (recommended)

```bash
docker compose up -d
```

Access on `http://localhost` (or configure reverse proxy via `networks.proxy`).

### Development

Serve `public/` with any static file server:

```bash
python -m http.server 8000 -d public
# or
npx serve public
```

## Architecture

```
public/
├── index.html           # main interface
├── css/style.css        # styling
├── js/
│   ├── app.js           # application logic
│   ├── totp.js          # TOTP implementation
│   ├── i18n.js          # i18n system
│   ├── translations/    # language files (fr, en, es)
│   └── vendor/          # qrcode.js
└── favicon.svg
```

**Stack**: vanilla JS (ES6 modules), no build step, no dependencies beyond QRCode.js

**Server**: nginx:alpine, read-only container, no persistent storage

## Security model

- Secret generation: browser `crypto.getRandomValues()` (CSPRNG)
- TOTP algorithm: RFC 6238 compliant
- Secrets never leave the device (except via QR code scan)
- **Physical presence required**: QR codes must be scanned in person, never shared digitally
- No server-side storage or logging
- Strict CSP + security headers (scripts restricted to self)
- Container runs read-only with `no-new-privileges`

## Internationalization

Language auto-detected from browser (`navigator.language`) or manually selected.

Add languages by creating `/public/js/translations/{lang}.json` and updating `supportedLangs` in `i18n.js`.

## License

See LICENSE file.
