use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

/// Sessão xHTTP ativa
struct XhttpSession {
    ssh_write: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    ssh_read: Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>,
}

static SESSIONS: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, XhttpSession>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[tokio::main]
async fn main() -> Result<(), Error> {
    let port = get_port();
    let status = get_status();
    let ssh_port = get_ssh_port();

    println!("[SDProxy] xHTTP SplitHTTP + SSL TUNNEL (v2.3.3)");
    println!("[SDProxy] Porta: {} | SSH: {} | Status: {}", port, ssh_port, status);

    let listener = TcpListener::bind(format!("[::]:{}", port)).await?;
    let status_arc = Arc::new(status);

    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                let status = status_arc.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client_stream, &status, ssh_port).await {
                        println!("[SDProxy] Erro cliente {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                println!("[SDProxy] Erro aceitar conexao: {}", e);
            }
        }
    }
}

async fn handle_client(stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), Error> {
    let mut peek_buf = [0u8; 1];
    let bytes_peeked = match timeout(Duration::from_secs(5), stream.peek(&mut peek_buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    if bytes_peeked > 0 && peek_buf[0] == 0x16 {
        return handle_tls_connection(stream, status, ssh_port).await;
    }

    handle_http_raw(stream, status, ssh_port).await
}

async fn handle_tls_connection(stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), Error> {
    let cert_path = "/opt/sdproxy/cert.pem";
    let key_path = "/opt/sdproxy/key.pem";

    let config = match build_tls_config(cert_path, key_path) {
        Ok(c) => c,
        Err(e) => {
            println!("[SDProxy][TLS] Erro config: {}", e);
            return Ok(());
        }
    };

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            println!("[SDProxy][TLS] Handshake falhou: {}", e);
            return Ok(());
        }
    };

    let (mut tls_read, tls_write) = tokio::io::split(tls_stream);
    let mut http_buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let mut end_of_headers = false;

    // Ler headers
    while !end_of_headers && http_buf.len() < 65536 {
        match timeout(Duration::from_secs(10), tls_read.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                http_buf.extend_from_slice(&chunk[..n]);
                if http_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    end_of_headers = true;
                }
            }
            _ => break,
        }
    }

    if http_buf.is_empty() {
        let tls_combined = tls_read.unsplit(tls_write);
        return handle_raw_tunnel_tls(tls_combined, ssh_port).await;
    }

    let http_str = String::from_utf8_lossy(&http_buf);
    let (method, path) = match parse_http_request(&http_str) {
        Some(m) => m,
        None => {
            let tls_combined = tls_read.unsplit(tls_write);
            return handle_raw_tunnel_tls(tls_combined, ssh_port).await;
        }
    };

    let tls_combined = tls_read.unsplit(tls_write);

    // Lógica xHTTP: Se o path contém um ID (ex: hex de 8+ chars) ou path /ssh/
    if is_xhttp_path(&path) {
        match method.as_str() {
            "GET" => handle_xhttp_get(tls_combined, &path, status, ssh_port).await,
            "POST" => handle_xhttp_post(tls_combined, &http_str, &path, status).await,
            _ => Ok(()),
        }
    } else {
        handle_ssl_tunnel_after_tls(tls_combined, status, ssh_port).await
    }
}

fn is_xhttp_path(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    if p.is_empty() { return false; }
    // Qualquer path com mais de 5 caracteres que não seja o padrão SSH do injector tratamos como xHTTP
    if p.len() > 5 || p.starts_with("ssh") { return true; }
    false
}

async fn handle_ssl_tunnel_after_tls(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin, status: &str, ssh_port: u16) -> Result<(), Error> {
    let resp = format!("HTTP/1.1 101 ({})\r\n\r\nHTTP/1.1 200 ({})\r\n\r\n", status, status);
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    let mut ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
    let _ = copy_bidirectional(&mut stream, &mut ssh_stream).await;
    Ok(())
}

async fn handle_raw_tunnel_tls(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin, ssh_port: u16) -> Result<(), Error> {
    let mut ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
    let _ = copy_bidirectional(&mut stream, &mut ssh_stream).await;
    Ok(())
}

async fn handle_http_raw(mut stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), Error> {
    let mut buf = vec![0u8; 8192];
    let n = match timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Ok(()),
    };

    let http_str = String::from_utf8_lossy(&buf[..n]);
    let (method, path) = match parse_http_request(&http_str) {
        Some(m) => m,
        None => return handle_raw_tunnel_with_data(buf[..n].to_vec(), stream, ssh_port).await,
    };

    if is_xhttp_path(&path) {
        match method.as_str() {
            "GET" => handle_xhttp_get(stream, &path, status, ssh_port).await,
            "POST" => handle_xhttp_post_raw(stream, &http_str, &path, status).await,
            _ => Ok(()),
        }
    } else {
        let resp = format!("HTTP/1.1 101 ({})\r\n\r\nHTTP/1.1 200 ({})\r\n\r\n", status, status);
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        let mut ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
        let _ = copy_bidirectional(&mut stream, &mut ssh_stream).await;
        Ok(())
    }
}

async fn handle_raw_tunnel_with_data(data: Vec<u8>, mut stream: TcpStream, ssh_port: u16) -> Result<(), Error> {
    let mut ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
    ssh_stream.write_all(&data).await?;
    let _ = copy_bidirectional(&mut stream, &mut ssh_stream).await;
    Ok(())
}

async fn handle_xhttp_get(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin, path: &str, status: &str, ssh_port: u16) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
    let (ssh_r, ssh_w) = ssh_stream.into_split();
    let ssh_r = Arc::new(Mutex::new(ssh_r));
    let ssh_w = Arc::new(Mutex::new(ssh_w));

    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), XhttpSession { ssh_write: ssh_w, ssh_read: ssh_r.clone() });
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Connection: keep-alive\r\n\
         X-Session-ID: {}\r\n\
         X-Status: {}\r\n\r\n",
        session_id, status
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    let mut buffer = [0u8; 16384];
    loop {
        let mut read_guard = ssh_r.lock().await;
        match timeout(Duration::from_secs(120), read_guard.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                if stream.write_all(&buffer[..n]).await.is_err() { break; }
                let _ = stream.flush().await;
            }
            _ => break,
        }
    }
    SESSIONS.lock().await.remove(&session_id);
    Ok(())
}

async fn handle_xhttp_post(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin, full_request: &str, path: &str, _status: &str) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    let content_length = extract_content_length(full_request).unwrap_or(0);
    
    let header_end = full_request.find("\r\n\r\n").map(|p| p + 4).unwrap_or(0);
    let mut body = full_request.as_bytes()[header_end..].to_vec();
    
    while body.len() < content_length {
        let mut chunk = vec![0u8; content_length - body.len()];
        let n = stream.read(&mut chunk).await?;
        if n == 0 { break; }
        body.extend_from_slice(&chunk[..n]);
    }

    if let Some(session) = SESSIONS.lock().await.get(&session_id) {
        let mut write_guard = session.ssh_write.lock().await;
        let _ = write_guard.write_all(&body).await;
        let _ = write_guard.flush().await;
    }

    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await?;
    Ok(())
}

async fn handle_xhttp_post_raw(mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin, full_request: &str, path: &str, _status: &str) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    let content_length = extract_content_length(full_request).unwrap_or(0);
    let header_end = full_request.find("\r\n\r\n").map(|p| p + 4).unwrap_or(0);
    let mut body = full_request.as_bytes()[header_end..].to_vec();
    
    while body.len() < content_length {
        let mut chunk = vec![0u8; content_length - body.len()];
        let n = stream.read(&mut chunk).await?;
        if n == 0 { break; }
        body.extend_from_slice(&chunk[..n]);
    }

    if let Some(session) = SESSIONS.lock().await.get(&session_id) {
        let mut write_guard = session.ssh_write.lock().await;
        let _ = write_guard.write_all(&body).await;
        let _ = write_guard.flush().await;
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await?;
    Ok(())
}

fn extract_session_id(path: &str) -> String {
    let p = path.trim_start_matches('/');
    let parts: Vec<&str> = p.split('/').collect();
    if parts.is_empty() { return "default".to_string(); }
    if parts[0] == "ssh" && parts.len() > 1 { return parts[1].to_string(); }
    parts[0].to_string()
}

fn extract_content_length(data: &str) -> Option<usize> {
    for line in data.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") { return line.split(':').nth(1)?.trim().parse().ok(); }
    }
    None
}

fn parse_http_request(data: &str) -> Option<(String, String)> {
    let first_line = data.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 { Some((parts[0].to_string(), parts[1].to_string())) } else { None }
}

fn build_tls_config(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig, Error> {
    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let mut key_reader = std::io::BufReader::new(key_file);
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut cert_reader)?.into_iter().map(Certificate).collect();
    let keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?.into_iter().map(PrivateKey).collect();
    let mut config = rustls::ServerConfig::builder()
        .with_cipher_suites(&rustls::ALL_CIPHER_SUITES)
        .with_kx_groups(&rustls::ALL_KX_GROUPS)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?
        .with_no_client_auth()
        .with_single_cert(certs, keys.into_iter().next().unwrap())
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
    
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn get_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 443;
    for i in 1..args.len() { if args[i] == "--port" || args[i] == "-p" { if i + 1 < args.len() { port = args[i + 1].parse().unwrap_or(443); } } }
    port
}

fn get_status() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut status = String::from("@SDProxy");
    for i in 1..args.len() { if args[i] == "--status" || args[i] == "-s" { if i + 1 < args.len() { status = args[i + 1].clone(); } } }
    status
}

fn get_ssh_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 22;
    for i in 1..args.len() { if args[i] == "--ssh-port" { if i + 1 < args.len() { port = args[i + 1].parse().unwrap_or(22); } } }
    port
}
