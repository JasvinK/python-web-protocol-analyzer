# Python Web Protocol Analyzer

## Overview
This project implements a Python networking tool that analyzes the behavior of a website by sending HTTP requests and examining the server response.

The program determines whether a website supports HTTP/2, extracts cookies from responses, and detects whether the website requires authentication.

## Features

- Parse URLs and construct HTTP requests
- Connect to web servers using TCP sockets
- Support HTTPS using TLS
- Detect HTTP/2 support using ALPN
- Follow HTTP redirects
- Extract cookies from response headers
- Detect password-protected pages

## How It Works

The program performs the following steps:

1. Parse the input URL
2. Establish a TCP or TLS connection to the server
3. Send an HTTP GET request
4. Read and parse the response headers
5. Detect HTTP/2 support
6. Extract cookies
7. Detect authentication requirements
8. Follow redirects if present

## Usage

Run the program by providing a URL through standard input.

Example:

```
echo "https://www.uvic.ca" | python3 WebTester.py
```

## Example Output

```
website: uvic.ca
1. Supports http2: yes
2. List of Cookies:
   cookie name: example_cookie
3. Password-protected: no
```

## File

```
WebTester.py
```

## Concepts Demonstrated

- Python networking
- Socket programming
- HTTP protocol
- HTTPS and TLS
- HTTP header parsing
- Web security concepts

## Author

Jasvin Kaur  
Computer Science – University of Victoria
