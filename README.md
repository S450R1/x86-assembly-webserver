# Minimal x86-64 Assembly Web Server

A tiny web server written in Intel-syntax x86-64 assembly that serves files over a very simple HTTP/1.0 response.

## Highlights
- Supports concurrent GET and POST requests (each client handled by a forked process)
- Written in Intel syntax x86-64 assembly (`server.s`)

## Usage
1. Start the server:
   - `./server`
2. From another terminal or machine, connect with netcat:
   - `nc <ip> 80`
3. To GET a file, send:
   - `GET <pathname>`
   - Example: `GET server.s`
   - You should receive a `HTTP/1.0 200 OK` header followed by the file contents if it exists.


4. To POST data to a file, send:
    - `POST <pathname>` followed by HTTP headers (must include `Content-Length`), a blank line, and the body.
      - Example POST request (each line must end with CRLF):
         ```
         POST notes.txt HTTP/1.1\r\nHost: localhost\r\nUser-Agent: python-requests/2.32.4\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: 15\r\n\r\nSample content!
         ```
      - Each line (including the blank line before the body) must end with `\r\n` (carriage return + line feed).
      - The server will write the body (`Sample content!`) to `notes.txt` and respond with `HTTP/1.0 200 OK`.

## Notes and Safety
- For learning purposes only. Do not use in production.
- No authentication, validation, or security hardening (e.g., path sanitization, directory traversal protection, MIME types, error handling) is provided.
- Tested on Linux x86-64.
