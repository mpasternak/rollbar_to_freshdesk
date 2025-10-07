# Rollbar to Freshdesk Webhook

A lightweight Python webhook server that receives Rollbar error notifications and automatically creates tickets in Freshdesk.

## What It Does

This webhook server:
- Listens for POST requests from Rollbar webhooks
- Extracts error information (title, level, environment, project, etc.)
- Creates a corresponding ticket in Freshdesk via API
- Returns immediately to Rollbar (always returns 200 OK)

## Design Philosophy

This code is intentionally written using **only Python standard library** with zero external dependencies. No pip install required, no virtualenv needed - just Python 3.10+.

**Note**: This code would be significantly cleaner and easier to read using Flask for the server and requests for HTTP calls. However, the stdlib-only approach was chosen for maximum portability and minimal deployment complexity. You can drop this single file on any server with Python and it just works.

## Requirements

- Python 3.10+ (uses only standard library)
- Freshdesk API token
- HTTPS reverse proxy (nginx, caddy, etc.)

## Installation

No installation required - uses only Python standard library.

```bash
chmod +x rollbar_to_freshdesk_webhook.py
```

## Usage

```bash
./rollbar_to_freshdesk_webhook.py \
  --freshdesk-subdomain iplweb \
  --freshdesk-token YOUR_FRESHDESK_API_TOKEN
```

### Command-Line Options

- `--host` - Host to bind to (default: 127.0.0.1)
- `--port` - Port to listen on (default: 9090)
- `--freshdesk-subdomain` - **Freshdesk subdomain** (required, e.g., `iplweb` for `iplweb.freshdesk.com`)
- `--freshdesk-token` - Freshdesk API token (required)
- `--freshdesk-pass` - Freshdesk API password (default: X)

**Note**: Provide only the subdomain part (e.g., `iplweb`). The code automatically appends `.freshdesk.com` to construct the API endpoint.

### Example

```bash
./rollbar_to_freshdesk_webhook.py \
  --host 127.0.0.1 \
  --port 9090 \
  --freshdesk-subdomain iplweb \
  --freshdesk-token GlmPiXsB-Ms-Cfwl0rJd
```

## HTTPS Requirement

**IMPORTANT**: This webhook server MUST run behind an HTTPS reverse proxy. Rollbar requires HTTPS for webhook endpoints, and the server itself only provides HTTP.

### Example nginx Configuration

Here's a minimal nginx configuration to proxy HTTPS requests to the webhook server:

```nginx
server {
    listen 443 ssl http2;
    server_name webhooks.example.com;

    ssl_certificate /etc/ssl/certs/your_cert.pem;
    ssl_certificate_key /etc/ssl/private/your_key.pem;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location /rollbar {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name webhooks.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Getting SSL Certificates

You can obtain free SSL certificates using [Let's Encrypt](https://letsencrypt.org/):

```bash
# Using certbot
sudo certbot --nginx -d webhooks.example.com
```

## Rollbar Configuration

1. In your Rollbar project, go to **Settings** → **Notifications** → **Webhook**
2. Add a new webhook with URL: `https://webhooks.example.com/rollbar`
3. Select which events should trigger the webhook (e.g., new errors, reactivated items)

## Running as a Service

### systemd Service Example

Create `/etc/systemd/system/rollbar-webhook.service`:

```ini
[Unit]
Description=Rollbar to Freshdesk Webhook
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/rollbar_webhook
ExecStart=/usr/bin/python3 /opt/rollbar_webhook/rollbar_to_freshdesk_webhook.py \
    --freshdesk-subdomain iplweb \
    --freshdesk-token YOUR_FRESHDESK_API_TOKEN
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable rollbar-webhook
sudo systemctl start rollbar-webhook
sudo systemctl status rollbar-webhook
```

## Troubleshooting

- Check logs: `sudo journalctl -u rollbar-webhook -f`
- Test webhook locally: `curl -X POST http://127.0.0.1:9090/rollbar -d '{"data":{"item":{"title":"test"}}}'`
- Verify nginx is proxying: check `/var/log/nginx/access.log` and `/var/log/nginx/error.log`

## License

Public domain / MIT
