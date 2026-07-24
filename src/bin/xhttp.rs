use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{timeout, Duration};

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

/// Sessão xHTTP ativa com canais para comunicação GET<->POST<->SSH
struct XhttpSession {
    post_tx: mpsc::Sender<Vec<u8>>,
    get_tx: mpsc::Sender<Vec<u8>>,
    active: Arc<RwLock<bool>>,
    next_seq: Arc<Mutex<u64>>,
}

static SESSIONS: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, XhttpSession>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[tokio::main]
async fn main() -> Result<(), Error> {
    let port = get_port();
    let status = get_status();
    let ssh_port = get_ssh_port();

    println!("[SDProxy] xHTTP SplitHTTP + XHTTP TLS (v2.3.9)");
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
        Err(_) => return Ok(()),
    };

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let mut http_buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let mut end_of_headers = false;

    while !end_of_headers && http_buf.len() < 65536 {
        match timeout(Duration::from_secs(10), tls_stream.read(&mut chunk)).await {
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
        let mut ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
        let _ = copy_bidirectional(&mut tls_stream, &mut ssh_stream).await;
        return Ok(());
    }

    let http_str = String::from_utf8_lossy(&http_buf);
    let (method, path) = match parse_http_request(&http_str) {
        Some(m) => m,
        None => {
            let mut ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
            let _ = copy_bidirectional(&mut tls_stream, &mut ssh_stream).await;
            return Ok(());
        }
    };

    if is_xhttp_path(&path) {
        match method.as_str() {
            "GET" => handle_xhttp_get_tls(tls_stream, &path, status, ssh_port).await,
            "POST" => handle_xhttp_post_tls(tls_stream, &http_buf, &path, status).await,
            _ => Ok(()),
        }
    } else {
        let resp = format!("HTTP/1.1 101 ({})\r\n\r\nHTTP/1.1 200 ({})\r\n\r\n", status, status);
        tls_stream.write_all(resp.as_bytes()).await?;
        tls_stream.flush().await?;
        let mut ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
        let _ = copy_bidirectional(&mut tls_stream, &mut ssh_stream).await;
        Ok(())
    }
}

fn is_xhttp_path(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    !p.is_empty() && (p.len() > 10 || p.contains("ssh") || p.contains("revive") || p.contains("session"))
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
        None => {
            let mut ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
            ssh_stream.write_all(&buf[..n]).await?;
            let _ = copy_bidirectional(&mut stream, &mut ssh_stream).await;
            return Ok(());
        }
    };

    if is_xhttp_path(&path) {
        match method.as_str() {
            "GET" => handle_xhttp_get_raw(stream, &path, status, ssh_port).await,
            "POST" => handle_xhttp_post_raw(stream, &buf[..n], &path, status).await,
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

async fn handle_xhttp_get_tls(mut tls_stream: impl AsyncReadExt + AsyncWriteExt + Unpin, path: &str, status: &str, ssh_port: u16) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
    let (mut ssh_read, mut ssh_write) = ssh_stream.into_split();
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(2048);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(2048);
    let active = Arc::new(RwLock::new(true));
    let next_seq = Arc::new(Mutex::new(0u64));

    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), XhttpSession { post_tx, get_tx: get_tx.clone(), active: active.clone(), next_seq });
    }

    tokio::spawn(async move {
        while let Some(data) = post_rx.recv().await {
            if ssh_write.write_all(&data).await.is_err() { break; }
            let _ = ssh_write.flush().await;
        }
    });

    let get_tx_for_read = get_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match timeout(Duration::from_secs(60), ssh_read.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => { if get_tx_for_read.send(buf[..n].to_vec()).await.is_err() { break; } }
                _ => break,
            }
        }
    });

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Connection: keep-alive\r\n\
         Cache-Control: no-cache, no-store, must-revalidate\r\n\
         Pragma: no-cache\r\n\
         Expires: 0\r\n\
         X-Session-ID: {}\r\n\
         X-Status: {}\r\n\r\n",
        session_id, status
    );

    tls_stream.write_all(response.as_bytes()).await?;
    tls_stream.flush().await?;

    while let Some(data) = get_rx.recv().await {
        if tls_stream.write_all(&data).await.is_err() { break; }
        let _ = tls_stream.flush().await;
    }
    SESSIONS.lock().await.remove(&session_id);
    Ok(())
}

async fn handle_xhttp_get_raw(mut stream: TcpStream, path: &str, status: &str, ssh_port: u16) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
    let (mut ssh_read, mut ssh_write) = ssh_stream.into_split();
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(2048);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(2048);
    let active = Arc::new(RwLock::new(true));
    let next_seq = Arc::new(Mutex::new(0u64));

    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), XhttpSession { post_tx, get_tx: get_tx.clone(), active: active.clone(), next_seq });
    }

    tokio::spawn(async move {
        while let Some(data) = post_rx.recv().await {
            if ssh_write.write_all(&data).await.is_err() { break; }
            let _ = ssh_write.flush().await;
        }
    });

    let get_tx_for_read = get_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match timeout(Duration::from_secs(60), ssh_read.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => { if get_tx_for_read.send(buf[..n].to_vec()).await.is_err() { break; } }
                _ => break,
            }
        }
    });

    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\nX-Session-ID: {}\r\nX-Status: {}\r\n\r\n", session_id, status);
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    while let Some(data) = get_rx.recv().await {
        if stream.write_all(&data).await.is_err() { break; }
        let _ = stream.flush().await;
    }
    SESSIONS.lock().await.remove(&session_id);
    Ok(())
}

async fn handle_xhttp_post_tls(mut tls_stream: impl AsyncReadExt + AsyncWriteExt + Unpin, full_request: &[u8], path: &str, _status: &str) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    let content_length = extract_content_length_from_bytes(full_request).unwrap_or(0);
    let header_end = full_request.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let mut body = full_request[header_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0u8; 8192];
        let n = tls_stream.read(&mut chunk).await?;
        if n == 0 { break; }
        body.extend_from_slice(&chunk[..n]);
    }
    if let Some(session) = SESSIONS.lock().await.get(&session_id) {
        let _ = session.post_tx.send(body[..content_length.min(body.len())].to_vec()).await;
    }
    tls_stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n").await?;
    Ok(())
}

async fn handle_xhttp_post_raw(mut stream: TcpStream, full_request: &[u8], path: &str, _status: &str) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    let content_length = extract_content_length_from_bytes(full_request).unwrap_or(0);
    let header_end = full_request.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let mut body = full_request[header_end..].to_vec();
    while body.len() < content_length {
        let mut chunk = vec![0u8; 8192];
        let n = stream.read(&mut chunk).await?;
        if n == 0 { break; }
        body.extend_from_slice(&chunk[..n]);
    }
    if let Some(session) = SESSIONS.lock().await.get(&session_id) {
        let _ = session.post_tx.send(body[..content_length.min(body.len())].to_vec()).await;
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n").await?;
    Ok(())
}

fn extract_session_id(path: &str) -> String {
    let p = path.trim_start_matches('/');
    let parts: Vec<&str> = p.split('/').collect();
    if parts.len() >= 2 && (parts[0] == "ssh" || parts[0] == "session" || parts[0] == "revive") {
        parts[1].to_string()
    } else if !parts.is_empty() {
        parts[0].to_string()
    } else {
        "default".to_string()
    }
}

fn extract_content_length_from_bytes(data: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(data);
    for line in s.lines() {
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
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
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
