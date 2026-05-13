//! static-http — a tiny HTTP/1.1 server that serves the same canned
//! "it works!" page to every request. Companion to `holesail-server`
//! for the demo: run this on a port, then tunnel that port over
//! HyperDHT.
//!
//! Why a dedicated binary instead of `socat SYSTEM:cat response.http`?
//! `socat`'s SYSTEM clause races the cat output against the socket
//! close — some HTTP clients see a truncated body or no body at all.
//! A small native server reads the request fully, writes the response
//! with `write_all`, and shuts down the socket cleanly so every
//! client sees the page.
//!
//! Usage:
//!     static-http              # listens on 127.0.0.1:8765
//!     static-http 9000         # listens on 127.0.0.1:9000
//!     HOST=0.0.0.0 static-http # listens on every interface

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::thread;

fn main() -> std::io::Result<()> {
    let port: u16 = env::args()
        .nth(1)
        .unwrap_or_else(|| "8765".to_string())
        .parse()
        .expect("port must be a 16-bit integer");
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());

    // Capture rustc version (best effort — falls back to "unknown"
    // if rustc isn't on PATH). Called once at startup, not per
    // request, so the cost is negligible.
    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let body = format!(
        "it works!\n\
         \n\
         Served by static-http (companion to holesail-rs)\n\
         rustc:    {}\n\
         host:     {} {} ({})\n",
        rustc_version,
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY,
    );

    let response = Arc::new(format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body,
    ));

    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr)?;
    println!(
        "static-http: listening on http://{} ({}-byte body)",
        addr,
        body.len()
    );
    println!("  Ctrl+C to stop");

    for conn in listener.incoming() {
        let sock = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let response = response.clone();
        thread::spawn(move || handle(sock, response));
    }
    Ok(())
}

fn handle(mut sock: std::net::TcpStream, response: Arc<String>) {
    // Drain the HTTP request (read until empty line). We don't
    // actually parse it — every request gets the same response.
    {
        let mut reader = BufReader::new(match sock.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        });
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    if line == "\r\n" || line == "\n" {
                        break; // end of headers
                    }
                }
                Err(_) => break,
            }
        }
    }
    // Send response; ignore broken-pipe errors (client gave up).
    let _ = sock.write_all(response.as_bytes());
    let _ = sock.flush();
    // Half-close write so the client sees EOF and stops waiting.
    let _ = sock.shutdown(std::net::Shutdown::Write);
}
