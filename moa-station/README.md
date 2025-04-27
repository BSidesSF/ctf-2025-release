# README

## Set Up Locally

```
docker compose up --build
```

## Exploit Chrome Extension Vulnerability

```
curl -X POST http://localhost:3003/submit-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://127.0.0.1:1234/exploit.html"}'
```

`exploit.html` is the one found in `solution/`, note that this URL must be hosted remotely - you can't view it from a `file://` URI as the extension won't be able to run on it.

## Notes

The extension is run via puppeteer in headful mode, we enable MV2 manifests via Chrome enterprise policy (see `ChromeEnterprisePolicy.json`). The `Dockerfile` sets this up for us.