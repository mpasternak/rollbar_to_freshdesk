#!/usr/bin/env python3
import http.server
import json
import base64
import unicodedata
import string
import sys
import argparse
from urllib import request, parse, error

# Limits (Freshdesk v2)
SUBJECT_MAX = 255
DESC_MAX    = 10_000  # practical safety cap

# Will be set from command-line args
FRESHDESK_URL = None
FRESHDESK_USER = None
FRESHDESK_PASS = None
REPORTER_EMAIL = None

def sanitize_text(s: str, limit: int | None = None) -> str:
    """Make text printable UTF-8 and optionally trim to 'limit' chars."""
    if s is None:
        return ""
    # Normalize + remove control chars except \n and \t
    s = unicodedata.normalize("NFC", str(s))
    printable = set(string.printable)  # ASCII set
    # Keep Unicode but drop C0/C1 control chars except \n \t
    s = "".join(ch for ch in s if (ch in ("\n", "\t")) or (unicodedata.category(ch)[0] != "C"))
    if limit is not None and len(s) > limit:
        s = s[:limit - 3] + "..."
    return s

class RollbarHandler(http.server.BaseHTTPRequestHandler):
    # ---------- Utilities ----------
    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}")

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        """Read request body supporting Content-Length and chunked encoding."""
        body = b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                line = self.rfile.readline().strip()
                if not line:
                    break
                try:
                    chunk_size = int(line, 16)
                except ValueError:
                    print(f"⚠️  Invalid chunk size line: {line!r}")
                    break
                if chunk_size == 0:
                    # consume trailing CRLF after last chunk
                    self.rfile.readline()
                    break
                body += self.rfile.read(chunk_size)
                self.rfile.readline()  # trailing CRLF
        else:
            length = int(self.headers.get("Content-Length", 0))
            if length:
                body = self.rfile.read(length)
        return body


    # ---------- Methods ----------
    def do_GET(self):
        print("📥 GET request received:")
        print(f"Path: {self.path}")
        for k, v in self.headers.items():
            print(f"  {k}: {v}")
        parsed = parse.urlparse(self.path)
        qs = parse.parse_qs(parsed.query)
        if qs:
            print("Query parameters:")
            for k, v in qs.items():
                print(f"  {k}: {v}")
        self._send_json({})

    def do_POST(self):
        print(f"📥 POST {self.path}")

        body = self._read_body()
        if not body:
            print("⚠️  Empty POST body received.")
            self._send_json({"warning": "empty body"}, 400)
            return

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            print(f"❌ JSON decode error: {e}")
            print("Raw body (first 200B):", body[:200])
            self._send_json({"error": "invalid JSON"}, 400)
            return

        print("📦 Parsed JSON payload:")
        print(json.dumps(data, indent=2))

        # ---- Extract Rollbar fields (best-effort) ----
        item = data.get("data", {}).get("item", {})
        title        = item.get("title", "Rollbar alert")
        environment  = item.get("environment", "unknown")
        level        = item.get("level", "error")
        # Convert level to string if it's an integer
        level_str    = str(level) if not isinstance(level, str) else level
        project_name = item.get("project", {}).get("name", "Unknown")
        url          = item.get("public_item_url", "")

        # Extract optional person and server info
        last_occurrence = item.get("last_occurrence", {})
        person = last_occurrence.get("person", {})
        server = last_occurrence.get("server", {})

        user_email   = person.get("email", REPORTER_EMAIL or "")
        person_username = person.get("username")
        person_email = person.get("email")
        server_hostname = server.get("host")

        # Build text (sanitized & limited)
        subject = sanitize_text(f"[{level_str.upper()}] {title}", SUBJECT_MAX)

        # Build HTML description with proper formatting
        description_parts = [
            "<h3>Rollbar Error Report</h3>",
            "<p>",
            f"<strong>Project:</strong> {project_name}<br>",
            f"<strong>Environment:</strong> {environment}<br>",
            f"<strong>Level:</strong> {level}<br>",
            f"<strong>URL:</strong> <a href='{url}'>{url}</a>",
            "</p>"
        ]

        # Add optional person/server info if available
        optional_info = []
        if person_username:
            optional_info.append(f"<strong>User:</strong> {person_username}")
        if person_email:
            optional_info.append(f"<strong>Email:</strong> {person_email}")
        if server_hostname:
            optional_info.append(f"<strong>Server:</strong> {server_hostname}")

        if optional_info:
            description_parts.append("<h4>Additional Information</h4>")
            description_parts.append("<p>")
            description_parts.append("<br>".join(optional_info))
            description_parts.append("</p>")

        description_parts.extend([
            "<h4>Full Payload</h4>",
            f"<pre>{json.dumps(data, indent=2)}</pre>"
        ])

        description_text = "".join(description_parts)
        description = sanitize_text(description_text, DESC_MAX)

        # ---- Freshdesk API v2 Ticket ----
        ticket_payload = {
            "email": user_email,                      # requester
            "subject": subject,
            "description": description,
            "priority": 1,                            # 1..4
            "status": 2,                              # 2 = Open
            "tags": ["rollbar", project_name, environment],
            "cc_emails": []                           # optional list
            # Add "group_id", "agent_id", "company_id", "custom_fields": {...} if needed
        }

        # ---- Send to Freshdesk v2 ----
        auth = base64.b64encode(f"{FRESHDESK_USER}:{FRESHDESK_PASS}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json"
        }
        payload_bytes = json.dumps(ticket_payload).encode("utf-8")

        print("📤 Sending to Freshdesk v2:")
        print(json.dumps(ticket_payload, indent=2))

        req = request.Request(FRESHDESK_URL, data=payload_bytes, headers=headers, method="POST")
        try:
            with request.urlopen(req, timeout=15) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                print(f"✅ Freshdesk responded: {resp.status} {resp.reason}")
                print("Headers:")
                for k, v in resp.headers.items():
                    print(f"  {k}: {v}")
                print("Response body:")
                print(resp_body)
        except error.HTTPError as e:
            print(f"❌ Freshdesk HTTP error: {e.code} {e.reason}")
            print("Headers:")
            for k, v in e.headers.items():
                print(f"  {k}: {v}")
            err_body = e.read().decode("utf-8", errors="replace")
            print("Response body:")
            print(err_body)
        except Exception as e:
            print(f"❌ Freshdesk request error: {e}")

        # Always 200 to webhook caller
        self._send_json({})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Rollbar to Freshdesk webhook server (should run behind HTTPS proxy)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9090, help="Port to listen on (default: 9090)")
    parser.add_argument(
        "--freshdesk-subdomain",
        required=True,
        help="Freshdesk subdomain (e.g., iplweb for iplweb.freshdesk.com)"
    )
    parser.add_argument("--freshdesk-token", required=True, help="Freshdesk API token")
    parser.add_argument("--freshdesk-pass", default="X", help="Freshdesk API password (default: X)")
    parser.add_argument("--reporter-email", help="Default reporter email (fallback if not in POST data)")

    args = parser.parse_args()

    # Set global configuration - automatically append .freshdesk.com
    FRESHDESK_URL = f"https://{args.freshdesk_subdomain}.freshdesk.com/api/v2/tickets"
    FRESHDESK_USER = args.freshdesk_token
    FRESHDESK_PASS = args.freshdesk_pass
    REPORTER_EMAIL = args.reporter_email

    server = http.server.HTTPServer((args.host, args.port), RollbarHandler)
    print(f"🚀 Listening on http://{args.host}:{args.port}/rollbar ... (Ctrl+C to stop)")
    print(f"📡 Freshdesk URL: {FRESHDESK_URL}")
    print(f"⚠️  NOTE: This server should run behind an HTTPS reverse proxy (e.g., nginx, caddy)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped.")
