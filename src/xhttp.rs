use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{timeout, Duration};

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

/// Tipo de erro unificado para o projeto
type XhttpError = Box<dyn std::error::Error + Send + Sync>;

/// Sessão xHTTP ativa com canais para comunicação GET<->POST<->SSH
#[allow(dead_code)]
struct XhttpSession {
    post_tx: mpsc::Sender<Vec<u8>>,
    get_tx: mpsc::Sender<Vec<u8>>,
    active: Arc<RwLock<bool>>,
}

static SESSIONS: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, XhttpSession>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[tokio::main]
async fn main() -> Result<(), XhttpError> {
    let port = get_port();
    let status = get_status();
    let ssh_port = get_ssh_port();

    println!("[BDRProxy] xHTTP SplitHTTP v3.3.1 (Integrated Fix)");
    println!("[xHTTP] Porta: {} | SSH: {} | Status: {}", port, ssh_port, status);

    let listener = TcpListener::bind(format!("[::]:{}", port)).await.map_err(|e| Box::new(e) as XhttpError)?;
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

async fn handle_xhttp_client(stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let mut peek_buf = [0u8; 3];
    let peek_result = timeout(Duration::from_secs(10), stream.peek(&mut peek_buf)).await;
    let bytes_peeked = match peek_result {
        Ok(Ok(n)) => n,
        _ => return Ok(()),
    };

    if bytes_peeked == 0 { return Ok(()); }
    let first_byte = peek_buf[0];

    if first_byte == 0x16 {
        return handle_tls_xhttp(stream, status, ssh_port).await;
    }

    if first_byte == 0x47 || first_byte == 0x50 || first_byte == 0x48 {
        return handle_http_xhttp_raw(stream, status, ssh_port).await;
    }

    handle_http_xhttp_raw(stream, status, ssh_port).await
}

async fn handle_tls_xhttp(stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let cert_path = "/opt/sdproxy/cert.pem";
    let key_path = "/opt/sdproxy/key.pem";

    let config = build_tls_config(cert_path, key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut tls_stream = acceptor.accept(stream).await.map_err(|e| Box::new(e) as XhttpError)?;

    let mut read_buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    let mut end_of_headers = false;

    while !end_of_headers && read_buf.len() < 65536 {
        match timeout(Duration::from_secs(15), tls_stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                read_buf.extend_from_slice(&chunk[..n]);
                if read_buf.windows(4).any(|w| w == b"\r\n\r\n") { end_of_headers = true; }
            }
            _ => return Ok(()),
        }
    }

    if !end_of_headers { return Ok(()); }
    let header_end = read_buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let http_str = String::from_utf8_lossy(&read_buf[..header_end]).to_string();
    let (method, path) = parse_http_request(&http_str).ok_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Invalid HTTP")) as XhttpError)?;

    match method.as_str() {
        "GET" => handle_xhttp_get_tls(&mut tls_stream, &path, status, ssh_port).await,
        "POST" => handle_xhttp_post_tls(&mut tls_stream, &read_buf, &path, status).await,
        _ => Ok(()),
    }
}

async fn handle_http_xhttp_raw(mut stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let mut buf = vec![0u8; 8192];
    let n = timeout(Duration::from_secs(10), stream.read(&mut buf)).await.map_err(|e| Box::new(e) as XhttpError)?.map_err(|e| Box::new(e) as XhttpError)?;
    let http_str = String::from_utf8_lossy(&buf[..n]);
    let (method, path) = match parse_http_request(&http_str) {
        Some(m) => m,
        None => {
            let mut ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
            ssh.write_all(&buf[..n]).await.map_err(|e| Box::new(e) as XhttpError)?;
            let (mut r, mut w) = stream.into_split();
            let (mut sr, mut sw) = ssh.into_split();
            let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
            return Ok(());
        }
    };

    match method.as_str() {
        "GET" => handle_xhttp_get_raw(&mut stream, &path, status, ssh_port).await,
        "POST" => handle_xhttp_post_raw(&mut stream, &buf[..n], &path, status).await,
        _ => Ok(()),
    }
}

async fn handle_xhttp_get_tls(tls_stream: &mut tokio_rustls::server::TlsStream<TcpStream>, path: &str, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut ssh_read, mut ssh_write) = ssh.into_split();
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(1024);
    let active = Arc::new(RwLock::new(true));

    SESSIONS.lock().await.insert(sid.clone(), XhttpSession { post_tx, get_tx: get_tx.clone(), active: active.clone() });

    let active_c = active.clone();
    tokio::spawn(async move {
        while let Some(data) = post_rx.recv().await {
            if !*active_c.read().await { break; }
            let _ = ssh_write.write_all(&data).await;
        }
    });

    let get_tx_c = get_tx.clone();
    tokio::spawn(async move {
        let mut b = vec![0u8; 16384];
        while let Ok(Ok(n)) = timeout(Duration::from_secs(600), ssh_read.read(&mut b)).await {
            if n == 0 || get_tx_c.send(b[..n].to_vec()).await.is_err() { break; }
        }
    });

    let resp = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Session-ID: {}\r\nX-Status: {}\r\n\r\n", sid, status);
    tls_stream.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;

    while let Some(data) = get_rx.recv().await {
        let chunk = format!("{:x}\r\n", data.len());
        if tls_stream.write_all(chunk.as_bytes()).await.is_err() { break; }
        if tls_stream.write_all(&data).await.is_err() { break; }
        if tls_stream.write_all(b"\r\n").await.is_err() { break; }
        let _ = tls_stream.flush().await;
    }
    Ok(())
}

async fn handle_xhttp_get_raw(stream: &mut TcpStream, path: &str, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut ssh_read, mut ssh_write) = ssh.into_split();
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(1024);
    let active = Arc::new(RwLock::new(true));

    SESSIONS.lock().await.insert(sid.clone(), XhttpSession { post_tx, get_tx: get_tx.clone(), active: active.clone() });

    tokio::spawn(async move {
        while let Some(data) = post_rx.recv().await {
            let _ = ssh_write.write_all(&data).await;
        }
    });

    let get_tx_c = get_tx.clone();
    tokio::spawn(async move {
        let mut b = vec![0u8; 16384];
        while let Ok(Ok(n)) = timeout(Duration::from_secs(600), ssh_read.read(&mut b)).await {
            if n == 0 || get_tx_c.send(b[..n].to_vec()).await.is_err() { break; }
        }
    });

    let resp = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Session-ID: {}\r\nX-Status: {}\r\n\r\n", sid, status);
    stream.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;

    while let Some(data) = get_rx.recv().await {
        let chunk = format!("{:x}\r\n", data.len());
        if stream.write_all(chunk.as_bytes()).await.is_err() { break; }
        if stream.write_all(&data).await.is_err() { break; }
        if stream.write_all(b"\r\n").await.is_err() { break; }
        let _ = stream.flush().await;
    }
    Ok(())
}

async fn handle_xhttp_post_tls(tls_stream: &mut tokio_rustls::server::TlsStream<TcpStream>, req: &[u8], path: &str, _: &str) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let cl = extract_content_length_from_bytes(req).unwrap_or(0);
    let h_end = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let mut body = req[h_end..].to_vec();

    while body.len() < cl {
        let mut b = vec![0u8; cl - body.len()];
        let n = tls_stream.read(&mut b).await.map_err(|e| Box::new(e) as XhttpError)?;
        if n == 0 { break; }
        body.extend_from_slice(&b[..n]);
    }

    if let Some(s) = SESSIONS.lock().await.get(&sid) { let _ = s.post_tx.send(body).await; }
    tls_stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.map_err(|e| Box::new(e) as XhttpError)?;
    Ok(())
}

async fn handle_xhttp_post_raw(stream: &mut TcpStream, req: &[u8], path: &str, _: &str) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let cl = extract_content_length_from_bytes(req).unwrap_or(0);
    let h_end = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let mut body = req[h_end..].to_vec();

    while body.len() < cl {
        let mut b = vec![0u8; cl - body.len()];
        let n = stream.read(&mut b).await.map_err(|e| Box::new(e) as XhttpError)?;
        if n == 0 { break; }
        body.extend_from_slice(&b[..n]);
    }

    if let Some(s) = SESSIONS.lock().await.get(&sid) { let _ = s.post_tx.send(body).await; }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.map_err(|e| Box::new(e) as XhttpError)?;
    Ok(())
}

fn parse_http_request(data: &str) -> Option<(String, String)> {
    let line = data.lines().next()?;
    let p: Vec<&str> = line.split_whitespace().collect();
    if p.len() >= 2 { Some((p[0].to_string(), p[1].to_string())) } else { None }
}

fn extract_path_info(path: &str) -> (String, Option<u64>) {
    let p = path.split('?').next().unwrap_or(path).trim_start_matches('/').split('/').collect::<Vec<&str>>();
    if p.is_empty() || p[0].is_empty() { return (String::new(), None); }
    if p.len() >= 2 {
        if ["ssh", "xhttp", "split"].contains(&p[0]) {
            return (p[1].to_string(), if p.len() >= 3 { p[2].parse().ok() } else { None });
        }
        return (p[0].to_string(), p[1].parse().ok());
    }
    (p[0].to_string(), None)
}

fn extract_content_length_from_bytes(data: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(data);
    for l in s.lines() {
        if l.to_lowercase().starts_with("content-length:") { return l.split(':').nth(1)?.trim().parse().ok(); }
    }
    None
}

fn build_tls_config(cp: &str, kp: &str) -> Result<rustls::ServerConfig, XhttpError> {
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cp).map_err(|e| Box::new(e) as XhttpError)?)).map_err(|e| Box::new(e) as XhttpError)?.into_iter().map(Certificate).collect();
    let keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(std::fs::File::open(kp).map_err(|e| Box::new(e) as XhttpError)?)).map_err(|e| Box::new(e) as XhttpError)?.into_iter().map(PrivateKey).collect();
    if certs.is_empty() || keys.is_empty() { return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Certs empty")) as XhttpError); }
    let mut c = rustls::ServerConfig::builder().with_safe_defaults().with_no_client_auth().with_single_cert(certs, keys.into_iter().next().unwrap()).map_err(|e| Box::new(e) as XhttpError)?;
    c.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    Ok(c)
}

fn get_port() -> u16 { std::env::args().enumerate().find(|(_, a)| a == "--port" || a == "-p").and_then(|(i, _)| std::env::args().nth(i+1)).and_then(|a| a.parse().ok()).unwrap_or(443) }
fn get_ssh_port() -> u16 { std::env::args().enumerate().find(|(_, a)| a == "--ssh-port").and_then(|(i, _)| std::env::args().nth(i+1)).and_then(|a| a.parse().ok()).unwrap_or(22) }
fn get_status() -> String { std::env::args().enumerate().find(|(_, a)| a == "--status" || a == "-s").and_then(|(i, _)| std::env::args().nth(i+1)).unwrap_or("@SDProxy".to_string()) }
