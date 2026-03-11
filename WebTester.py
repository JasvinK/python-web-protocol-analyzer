#!/usr/bin/env python3
import sys
import socket
import ssl

CRLF = "\r\n"

# -----------------------------
# URL parsing (no urllib.parse)
# -----------------------------
def parse_uri(uri: str):
    uri = uri.strip()

    if "://" in uri:
        scheme, rest = uri.split("://", 1)
        scheme = scheme.lower()
    else:
        # default if scheme missing
        scheme = "https"
        rest = uri

    # split host[:port] and path
    if "/" in rest:
        hostport, path_rest = rest.split("/", 1)
        path = "/" + path_rest
    else:
        hostport = rest
        path = "/"

    # remove accidental trailing spaces
    hostport = hostport.strip()

    # host and optional port
    if ":" in hostport:
        host, port_str = hostport.rsplit(":", 1)
        host = host.strip()
        port = int(port_str.strip())
    else:
        host = hostport
        port = 443 if scheme == "https" else 80

    return scheme, host, port, path


# -----------------------------
# HTTP request / response utils
# -----------------------------
def build_request(host: str, path: str) -> bytes:
    # Always send HTTP/1.1 request lines
    req_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Connection: close",
        "",  # blank line to end headers
        "",
    ]
    return CRLF.join(req_lines).encode("utf-8")


def recv_all(sock) -> bytes:
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def split_header_body(resp: bytes):
    sep = b"\r\n\r\n"
    i = resp.find(sep)
    if i == -1:
        header_text = resp.decode("iso-8859-1", errors="replace")
        return header_text, b""
    header_text = resp[:i].decode("iso-8859-1", errors="replace")
    body = resp[i + 4 :]
    return header_text, body


def parse_status_code(header_text: str):
    # First line: HTTP/1.1 200 OK
    first_line = header_text.split("\r\n", 1)[0]
    parts = first_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


def get_headers(header_text: str):
    # dict: header_name_lower -> list of values
    headers = {}
    lines = header_text.split("\r\n")
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        headers.setdefault(k, []).append(v)
    return headers


# -----------------------------
# Cookie parsing
# -----------------------------
def parse_set_cookie(value: str):
    # Set-Cookie: NAME=VALUE; expires=...; domain=...;
    parts = [p.strip() for p in value.split(";")]
    name_value = parts[0]
    name = name_value.split("=", 1)[0].strip()

    expires = None
    domain = None
    for p in parts[1:]:
        pl = p.lower()
        if pl.startswith("expires="):
            expires = p[len("expires="):].strip()
        elif pl.startswith("domain="):
            domain = p[len("domain="):].strip()

    return name, expires, domain


# -----------------------------
# Redirect handling
# -----------------------------
def resolve_location(curr_scheme, curr_host, curr_port, location: str):
    location = location.strip()

    # absolute URL
    if "://" in location:
        return parse_uri(location)

    # absolute path on same host
    if location.startswith("/"):
        return curr_scheme, curr_host, curr_port, location

    # relative path (treat as /relative)
    return curr_scheme, curr_host, curr_port, "/" + location


# -----------------------------
# One fetch (one request)
# -----------------------------
def fetch_once(scheme, host, port, path):
    supports_h2 = False

    def open_tls(alpn_list):
        raw = socket.create_connection((host, port), timeout=10)
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(alpn_list)
        return ctx.wrap_socket(raw, server_hostname=host)

    # --- HTTPS case ---
    if scheme == "https":
        # (1) Probe for HTTP/2 support
        probe = open_tls(["h2", "http/1.1"])
        selected = probe.selected_alpn_protocol()
        supports_h2 = (selected == "h2")
        probe.close()

        # (2) Open a new connection that forces HTTP/1.1 so we can send HTTP/1.1 text
        sock = open_tls(["http/1.1"])
    else:
        # --- HTTP case ---
        sock = socket.create_connection((host, port), timeout=10)

    req = build_request(host, path)
    sock.sendall(req)

    resp = recv_all(sock)
    sock.close()

    header_text, body = split_header_body(resp)
    code = parse_status_code(header_text)
    headers = get_headers(header_text)

    return code, headers, supports_h2



# -----------------------------
# Main
# -----------------------------
def main():
    uri = sys.stdin.readline()
    if not uri:
        return

    scheme, host, port, path = parse_uri(uri)

    supports_h2_any = False
    cookies = []  # list of (name, expires, domain)
    password_protected = False

    # follow redirects (limit to avoid accidental loops)
    for _ in range(10):
        try:
            code, headers, supports_h2 = fetch_once(scheme, host, port, path)
        except Exception:
            # Invalid host / DNS failure / blocked network
            print(f"website: {host}")
            print("1. Supports http2: no")
            print("2. List of Cookies:")
            print("no cookies found")
            print("3. Password-protected: no")
            return
        
        supports_h2_any = supports_h2_any or supports_h2

        # cookies from this response
        for sc in headers.get("set-cookie", []):
            cookies.append(parse_set_cookie(sc))

        # password-protected?
        if code == 401 or "www-authenticate" in headers:
            password_protected = True

        # redirect?
        if code in (301, 302) and "location" in headers:
            location = headers["location"][0]
            scheme, host, port, path = resolve_location(scheme, host, port, location)
            continue

        break

    # Output format (keep it simple + consistent)
    print(f"website: {host}")
    print(f"1. Supports http2: {'yes' if supports_h2_any else 'no'}")

    print("2. List of Cookies:")
    if not cookies:
        print("no cookies found")
    else:
        for (name, expires, domain) in cookies:
            out = f"cookie name: {name}"
            if expires:
                out += f", expires time: {expires}"
            if domain:
                out += f", domain name: {domain}"
            print(out)

    print(f"3. Password-protected: {'yes' if password_protected else 'no'}")


if __name__ == "__main__":
    main()
