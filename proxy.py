import argparse
import re

import socket
import signal
import sys


# Get the command line arguments
def get_args():
    parser = argparse.ArgumentParser(description="DNS Injector")
    parser.add_argument("-m", "--mode", help="The mode the proxy will operate with")
    parser.add_argument("address", help="The IP address of the proxy")
    parser.add_argument("port", help="The port of the proxy")
    args = parser.parse_args()

    return args


# In addition to forwarding packets it should look for info in the packets and log them in info_1.txt, so append
# The info to look for are
# Username/emails and passwords in query params or in forms
# Credit card numbers or SSN
# Cookies in the HTTP request


# HINT: use regex to capture nuances of different format types, look both at req and res packets
# HINT: info can be passed in the URL and headers too
def passive():
    pass


# In addition to forwarding packets it should inject JS code that should perform fingerprinting on the cient
# Info to gather: user agent, screen resolution, language
# Those info should be then sent back to the proxy with a GET request using:
# http://proxy ip address/?user-agent=USER AGENT&screen=SCREEN RES&lang=LANGUAGE
# On receive those info should be parsed and logged in info_2.txt

# HINT: For user-agent and language look into JS navigator module
# HINT: For screen resolution look into JS window module
# HINT: To send the strings as query param they must be encoded correctly


# Also for predefined domains a fake login page should be used to capture credentials ie. user search example.com
def active():
    pass

def handle_client(client_sock: socket, forward_ip, forward_port):
    # Connect to the server to forward requests to
    # This are the result that we have to retrieve from the data sent to us by the client
    # server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server_sock.connect((forward_ip, forward_port))
    
    while True:
        # Receive data from the client
        client_data = get_data(client_sock)

        request = client_data.decode("utf-8")

        print(f"[*] Received {len(client_data)} bytes from the client.")

        first_line = request.split('\n')[0]

        # Get the URL from the request
        url = get_url(first_line)

        if url:
            print(f"[*] URL: {url}")
        else:
            continue

        http_pos = url.find("://")  # find pos of ://
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos + 3):]  # get the rest of the url

        print(temp)
        
        port_pos = temp.find(":")  # find the port pos (if any)

        # Find end of the web server
        webserver_pos = temp.find("/")
        if webserver_pos == -1:
            webserver_pos = len(temp)
        
        webserver = ""
        port = -1
        if port_pos == -1 or webserver_pos < port_pos:  # default port
            port = 80
            webserver = temp[:webserver_pos]
        else:  # specific port
            port = int((temp[(port_pos + 1):])[:webserver_pos - port_pos - 1])
            webserver = temp[:port_pos]
        
        path = url[http_pos + 3 + len(webserver) + (0 if port == 80 else len(str(port)) + 1):]
        
        # Forward the request to the target server and fetch the response
        target_server = (webserver, port)
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        proxy_socket.connect(target_server)

        print(proxy_socket)

        proxy_socket.sendall(request.encode())

        # Receive the response from the target server
        response = get_data(proxy_socket)

        print(f"[*] Received {len(response)} bytes from the server.")
        print(response)

        # The request from the client must be sent to the server



        # Send the data to the server
        # server_sock.sendall(client_data)

        # Receive the response from the server
        # server_data = server_sock.recv(4096)
        # if not server_data:
            # break

        # Send the response back to the client
        # client_sock.sendall(server_data)

    # Close the server socket
    # server_sock.close()

def get_data(socket: socket):
    data = b""
    while True:
        part = socket.recv(4096)
        data += part
        if len(part) < 4096:
            # Either 0 or end of data
            break

    return data


def get_url(req: str) -> str:
    url_pattern = r'(http[s]?://[^ \s]+)'

    # Find URL using the regular expression
    url_match = re.search(url_pattern, req)

    # Check if a URL was found
    if url_match:
        return url_match.group(1)
    
    return None
        

def main():
    args = get_args()

    print(args)

    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    # We have them from the command line 
    # listen_ip = "0.0.0.0"
    # listen_port = 9999
    forward_ip = "192.168.1.100"  # The IP of the server you want to forward requests to
    forward_port = 80             # The port of the server you want to forward requests to
    
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
        handle_client(client_sock, forward_ip, forward_port)

        # Close the client socket
        client_sock.close()
        print("[*] Connection closed.")

if __name__ == "__main__":
    main()
