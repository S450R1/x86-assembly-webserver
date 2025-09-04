# Minimal x86-64 Assembly Web Server

A tiny web server written in Intel-syntax x86-64 assembly that serves files over a very simple HTTP/1.0 response.

## Highlights
- Supports concurrent GET requests (each client handled by a forked process)
- Written in Intel syntax x86-64 assembly (`server.s`)

## Usage
1. Start the server:
   - `./server`
2. From another terminal or machine, connect with netcat:
   - `nc <ip> 80`
3. Send a GET request with a pathname (relative to the server’s working directory), then press Enter:
   - `GET <pathname>`
   - Example: `GET server.s`

You should receive a `HTTP/1.0 200 OK` header followed by the file contents if it exists.

## Notes and Safety
- For learning purposes only. Do not use in production.
- No authentication, validation, or security hardening (e.g., path sanitization, directory traversal protection, MIME types, error handling) is provided.
- Tested on Linux x86-64.
