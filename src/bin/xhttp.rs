use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{timeout, Duration};

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

/// Sessão xHTTP ativa com canais para comunicação GET<->POST<->SSH
struct XhttpSession {
    post_tx: mpsc::Sender<Vec<u8>>,
    #[allow(dead_code)]
    get_tx: mpsc::Sender<Vec<u8>>,
    #[allow(dead_code)]
    active: Arc<RwLock<bool>>,
}

static SESSIONS: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, XhttpSession>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[tokio::main]
async fn main() -> Result<(), Error> {
    let port = get_port();
    let status = get_status();
    let ssh_port = get_ssh_port();

    println!("[BDRProxy] xHTTP SplitHTTP v2.5.0 (Sync SDProxy)");
    println!("[xHTTP] Porta: {} | SSH: {} | Status: {}", port, ssh_port, status);

    let listener = TcpListener::bind(format!("[::]:{}", port)).await?;
    let status_arc = Arc::new(status);

    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                let status = status_arc.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_xhttp_client(client_stream, &status, ssh_port).await {
                        println!("[xHTTP] Erro cliente {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                println!("[xHTTP] Erro aceitar conexao: {}", e);
            }
        }
    }
}

async fn handle_xhttp_client(stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), Error> {
    let mut peek_buf = [0u8; 3];
    let peek_result = timeout(Duration::from_secs(10), stream.peek(&mut peek_buf)).await;
    let bytes_peeked = match peek_result {
        Ok(Ok(n)) => n,
        _ => return Ok(()),
    };

    if bytes_peeked == 0 { return Ok(()); }
    let first_byte = peek_buf[0];

    // Detecta TLS (0x16 = TLS ClientHello)
    if first_byte == 0x16 {
        return handle_tls_xhttp(stream, status, ssh_port).await;
    }

    // Detecta HTTP (GET, POST, HEAD)
    if first_byte == 0x47 || first_byte == 0x50 || first_byte == 0x48 {
        return handle_http_xhttp_raw(stream, status, ssh_port).await;
    }

    handle_http_xhttp_raw(stream, status, ssh_port).await
}

async fn handle_tls_xhttp(stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), Error> {
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

    let mut tls_read_buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    let mut end_of_headers = false;
    let mut total_read = 0usize;

    while !end_of_headers && total_read < 65536 {
        match timeout(Duration::from_secs(15), tls_stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                total_read += n;
                tls_read_buf.extend_from_slice(&chunk[..n]);
                if tls_read_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    end_of_headers = true;
                }
            }
            _ => return Ok(()),
        }
    }

    let header_end_pos = tls_read_buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
    let header_part = &tls_read_buf[..header_end_pos + 4];
    let http_str: String = String::from_utf8_lossy(&tls_read_buf[..header_end_pos]).to_string();
    let content_length = extract_content_length_from_bytes(header_part).unwrap_or(0);
    let body_already = total_read - (header_end_pos + 4);

    if content_length > 0 && body_already < content_length {
        let remaining = content_length - body_already;
        let mut body_buf = vec![0u8; remaining];
        let mut body_read = 0;
        while body_read < remaining {
            match timeout(Duration::from_secs(30), tls_stream.read(&mut body_buf[body_read..])).await {
                Ok(Ok(n)) if n > 0 => body_read += n,
                _ => break,
            }
        }
        tls_read_buf.extend_from_slice(&body_buf[..body_read]);
    }

    let (method, path) = match parse_http_request(&http_str) {
        Some(m) => m,
        None => return Ok(()),
    };

    match method.as_str() {
        "GET" => handle_xhttp_get_tls(&mut tls_stream, &path, status, ssh_port).await,
        "POST" => handle_xhttp_post_tls(&mut tls_stream, &tls_read_buf, &path, status).await,
        _ => {
            let resp = format!("HTTP/1.1 101 ({})\r\n\r\nHTTP/1.1 200 ({})\r\n\r\n", status, status);
            tls_stream.write_all(resp.as_bytes()).await?;
            let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
            let (mut r, mut w) = tokio::io::split(tls_stream);
            let (mut sr, mut sw) = ssh_stream.into_split();
            let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
            Ok(())
        }
    }
}

async fn handle_http_xhttp_raw(mut stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), Error> {
    let mut buf = vec![0u8; 65536];
    let n = match timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Ok(()),
    };

    let http_str = String::from_utf8_lossy(&buf[..n]);
    let header_end = http_str.find("\r\n\r\n").unwrap_or(0);
    let header_str = if header_end > 0 { &http_str[..header_end] } else { &http_str };

    let (method, path) = match parse_http_request(header_str) {
        Some(m) => m,
        None => {
            let mut ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
            ssh_stream.write_all(&buf[..n]).await?;
            let (mut r, mut w) = stream.into_split();
            let (mut sr, mut sw) = ssh_stream.into_split();
            let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
            return Ok(());
        }
    };

    match method.as_str() {
        "GET" => handle_xhttp_get_raw(&mut stream, &path, status, ssh_port).await,
        "POST" => handle_xhttp_post_raw(&mut stream, &buf[..n], &path, status).await,
        _ => {
            let resp = format!("HTTP/1.1 101 ({})\r\n\r\nHTTP/1.1 200 ({})\r\n\r\n", status, status);
            stream.write_all(resp.as_bytes()).await?;
            let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
            let (mut r, mut w) = stream.into_split();
            let (mut sr, mut sw) = ssh_stream.into_split();
            let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
            Ok(())
        }
    }
}

async fn handle_xhttp_get_tls(tls_stream: &mut tokio_rustls::server::TlsStream<TcpStream>, path: &str, status: &str, ssh_port: u16) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    if session_id.is_empty() { return Ok(()); }

    let ssh_stream = match TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let (mut ssh_read, mut ssh_write) = ssh_stream.into_split();
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(1024);
    let active = Arc::new(RwLock::new(true));

    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), XhttpSession { post_tx, get_tx: get_tx.clone(), active: active.clone() });
    }

    let active_write = active.clone();
    tokio::spawn(async move {
        while let Some(data) = post_rx.recv().await {
            if !*active_write.read().await { break; }
            if ssh_write.write_all(&data).await.is_err() { break; }
            let _ = ssh_write.flush().await;
        }
    });

    let active_read = active.clone();
    let get_tx_for_read = get_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            if !*active_read.read().await { break; }
            match timeout(Duration::from_secs(60), ssh_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => { if get_tx_for_read.send(buf[..n].to_vec()).await.is_err() { break; } }
                _ => {}
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
         X-Status: {}\r\n\r\n",
        status
    );

    tls_stream.write_all(response.as_bytes()).await?;
    tls_stream.flush().await?;

    while let Some(data) = get_rx.recv().await {
        if tls_stream.write_all(&data).await.is_err() { break; }
        let _ = tls_stream.flush().await;
    }

    *active.write().await = false;
    SESSIONS.lock().await.remove(&session_id);
    Ok(())
}

async fn handle_xhttp_get_raw(stream: &mut TcpStream, path: &str, status: &str, ssh_port: u16) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    if session_id.is_empty() { return Ok(()); }

    let ssh_stream = match TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let (mut ssh_read, mut ssh_write) = ssh_stream.into_split();
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(1024);
    let active = Arc::new(RwLock::new(true));

    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), XhttpSession { post_tx, get_tx: get_tx.clone(), active: active.clone() });
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
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => { if get_tx_for_read.send(buf[..n].to_vec()).await.is_err() { break; } }
                _ => {}
            }
        }
    });

    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\nX-Status: {}\r\n\r\n", status);
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    while let Some(data) = get_rx.recv().await {
        if stream.write_all(&data).await.is_err() { break; }
        let _ = stream.flush().await;
    }

    *active.write().await = false;
    SESSIONS.lock().await.remove(&session_id);
    Ok(())
}

async fn handle_xhttp_post_tls(tls_stream: &mut tokio_rustls::server::TlsStream<TcpStream>, full_request: &[u8], path: &str, _status: &str) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    let content_length = extract_content_length_from_bytes(full_request).unwrap_or(0);
    let header_end = full_request.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let body_in_request = full_request.len() - header_end;

    if let Some(session) = SESSIONS.lock().await.get(&session_id) {
        let mut body = if body_in_request >= content_length {
            full_request[header_end..header_end + content_length].to_vec()
        } else {
            let mut body = full_request[header_end..].to_vec();
            let remaining = content_length - body_in_request;
            let mut buf = vec![0u8; remaining];
            let mut read = 0;
            while read < remaining {
                match timeout(Duration::from_secs(30), tls_stream.read(&mut buf[read..])).await {
                    Ok(Ok(n)) if n > 0 => read += n,
                    _ => break,
                }
            }
            body.extend_from_slice(&buf[..read]);
            body
        };
        body.truncate(content_length);
        let _ = session.post_tx.send(body).await;
    }
    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nX-Status: {}\r\n\r\n", _status);
    tls_stream.write_all(resp.as_bytes()).await?;
    tls_stream.flush().await?;
    Ok(())
}

async fn handle_xhttp_post_raw(stream: &mut TcpStream, full_request: &[u8], path: &str, _status: &str) -> Result<(), Error> {
    let session_id = extract_session_id(path);
    let content_length = extract_content_length_from_bytes(full_request).unwrap_or(0);
    let header_end = full_request.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let body_in_request = full_request.len() - header_end;

    if let Some(session) = SESSIONS.lock().await.get(&session_id) {
        let mut body = if body_in_request >= content_length {
            full_request[header_end..header_end + content_length].to_vec()
        } else {
            let mut body = full_request[header_end..].to_vec();
            let remaining = content_length - body_in_request;
            let mut buf = vec![0u8; remaining];
            let mut read = 0;
            while read < remaining {
                match timeout(Duration::from_secs(30), stream.read(&mut buf[read..])).await {
                    Ok(Ok(n)) if n > 0 => read += n,
                    _ => break,
                }
            }
            body.extend_from_slice(&buf[..read]);
            body
        };
        body.truncate(content_length);
        let _ = session.post_tx.send(body).await;
    }
    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nX-Status: {}\r\n\r\n", _status);
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn parse_http_request(data: &str) -> Option<(String, String)> {
    let first_line = data.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 { Some((parts[0].to_string(), parts[1].to_string())) } else { None }
}

fn extract_session_id(path: &str) -> String {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() >= 2 {
        parts[1].to_string()
    } else if parts.len() == 1 && !parts[0].is_empty() {
        parts[0].to_string()
    } else {
        String::new()
    }
}

fn extract_content_length_from_bytes(data: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(data);
    for line in s.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            return line.split(':').nth(1)?.trim().parse().ok();
        }
    }
    None
}

fn build_tls_config(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig, Error> {
    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let mut key_reader = std::io::BufReader::new(key_file);

    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    let keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?
        .into_iter()
        .map(PrivateKey)
        .collect();

    if certs.is_empty() || keys.is_empty() {
        return Err(Error::new(std::io::ErrorKind::Other, "Certs ou keys vazios"));
    }

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.into_iter().next().unwrap())
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
    
    // Suporte a HTTP/1.1 e HTTP/2 (SplitHTTP pode usar ambos)
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    
    Ok(config)
}

fn get_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    for i in 1..args.len() {
        if (args[i] == "--port" || args[i] == "-p") && i + 1 < args.len() {
            return args[i + 1].parse().unwrap_or(443);
        }
    }
    443
}

fn get_ssh_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    for i in 1..args.len() {
        if args[i] == "--ssh-port" && i + 1 < args.len() {
            return args[i + 1].parse().unwrap_or(22);
        }
    }
    22
}

fn get_status() -> String {
    let args: Vec<String> = std::env::args().collect();
    for i in 1..args.len() {
        if (args[i] == "--status" || args[i] == "-s") && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    "@SDProxy".to_string()
}
