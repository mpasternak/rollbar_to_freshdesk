# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a single-file Python webhook server that receives Rollbar error notifications and creates tickets in Freshdesk. The entire application is contained in `rollbar_to_freshdesk_webhook.py`.

**Key Design Constraint**: Uses **only Python 3.10+ standard library** - no external dependencies. This is intentional for maximum portability and zero-dependency deployment.

## Running the Application

### Start the webhook server:
```bash
./rollbar_to_freshdesk_webhook.py \
  --freshdesk-subdomain YOUR_SUBDOMAIN \
  --freshdesk-token YOUR_API_TOKEN
```

Additional options:
- `--host` - Bind host (default: 127.0.0.1)
- `--port` - Listen port (default: 9090)
- `--freshdesk-pass` - API password (default: X)

### Test locally:
```bash
curl -X POST http://127.0.0.1:9090/rollbar -d '{"data":{"item":{"title":"test"}}}'
```

## Architecture

### Single-File Structure (rollbar_to_freshdesk_webhook.py)

1. **RollbarHandler** (extends `http.server.BaseHTTPRequestHandler`)
   - `do_POST()`: Main webhook handler
     - Reads request body (supports chunked encoding via `_read_body()`)
     - Parses Rollbar JSON payload
     - Extracts: title, environment, level, project, person, server info
     - Constructs Freshdesk ticket with HTML description
     - Sends ticket to Freshdesk API v2 using stdlib `urllib`
     - Always returns 200 OK to Rollbar (fire-and-forget pattern)

   - `do_GET()`: Debug endpoint that logs headers/params

2. **sanitize_text()**: Utility function
   - Normalizes Unicode (NFC)
   - Removes control characters (except \n, \t)
   - Truncates to specified limits (Freshdesk has 255 char subject, ~10K description limits)

3. **Global Configuration**
   - `FRESHDESK_URL`: Constructed from subdomain as `https://{subdomain}.freshdesk.com/api/v2/tickets`
   - `FRESHDESK_USER/PASS`: API credentials from command-line args

### Key Implementation Details

- **No external HTTP libraries**: Uses `urllib.request` instead of `requests`
- **No Flask/FastAPI**: Uses `http.server.HTTPServer` and custom request handler
- **Authentication**: Basic Auth with Freshdesk API token as username
- **Error handling**: Logs Freshdesk API errors but still returns 200 to Rollbar
- **Payload format**: Rollbar sends nested JSON at `data.item.*`, Freshdesk expects flat ticket structure

## Deployment Context

- **MUST run behind HTTPS reverse proxy** (nginx, caddy, etc.) because Rollbar requires HTTPS webhooks
- Typically deployed as systemd service
- See README.md for nginx configuration examples

## Development Guidelines

When modifying this code:
- Maintain zero external dependencies (stdlib only)
- Keep logging verbose (emojis for visual scanning: 📥📦✅❌⚠️)
- Always return 200 to webhook caller (Rollbar) regardless of Freshdesk API success/failure
- Respect Freshdesk API limits: subject max 255 chars, description max ~10K chars
- Sanitize all user-controlled text before sending to Freshdesk
