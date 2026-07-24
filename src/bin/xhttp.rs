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

static IP_SESSIONS: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, String>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[tokio::main]
async fn main() -> Result<(), XhttpError> {
    let port = get_port();
    let status = get_status();
    let ssh_port = get_ssh_port();

    println!("[BDRProxy] xHTTP v3.3.2 (Dual Mode: XHTTP + SSL Tunnel)");
    println!("[xHTTP] Porta: {} | SSH Backend: 127.0.0.1:{}", port, ssh_port);

    let listener = TcpListener::bind(format!("[::]:{}", port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let status_arc = Arc::new(status);

    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                let _ = client_stream.set_nodelay(true);
                let status = status_arc.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_xhttp_client(client_stream, &status, ssh_port).await {
                        println!("[xHTTP] Erro em {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                println!("[xHTTP] Erro aceitar conexao: {}", e);
            }
        }
    }
}

async fn handle_xhttp_client(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    let client_ip = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
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
        return handle_tls_dual(stream, status, ssh_port, client_ip).await;
    }

    // Detecta HTTP direto (não encriptado)
    if first_byte == 0x47 || first_byte == 0x50 || first_byte == 0x48 {
        return handle_http_xhttp_raw(stream, status, ssh_port).await;
    }

    // Fallback para SSH direto (Proxy puro)
    handle_ssh_direct(stream, ssh_port).await
}

async fn handle_tls_dual(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
    client_ip: String,
) -> Result<(), XhttpError> {
    let cert_path = "/opt/sdproxy/cert.pem";
    let key_path = "/opt/sdproxy/key.pem";

    let mut config = build_tls_config(cert_path, key_path)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut tls_stream = acceptor.accept(stream).await.map_err(|e| Box::new(e) as XhttpError)?;

    // Sniffing após TLS: Verificamos se o cliente envia HTTP
    let mut buf = vec![0u8; 4096];
    let n = match timeout(Duration::from_secs(5), tls_stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            // Se timeout ou erro, tentamos tratar como SSL Tunnel direto
            return handle_ssh_direct_tls(tls_stream, ssh_port, None).await;
        }
    };

    let data = &buf[..n];
    let http_str = String::from_utf8_lossy(data);
    
    // Se for um método HTTP válido, segue para XHTTP
    if http_str.starts_with("GET ") || http_str.starts_with("POST ") || http_str.starts_with("HEAD ") {
        let (method, path) = parse_http_request(&http_str).unwrap();
        match method.as_str() {
            "GET" => return handle_xhttp_get_tls(&mut tls_stream, &path, status, ssh_port).await,
            "POST" => return handle_xhttp_post_tls(&mut tls_stream, data, &path, status).await,
            _ => {}
        }
    }

    // Se não for HTTP, é um SSL Tunnel (SSH sobre TLS)
    handle_ssh_direct_tls(tls_stream, ssh_port, Some(data.to_vec())).await
}

async fn handle_ssh_direct(mut stream: TcpStream, ssh_port: u16) -> Result<(), XhttpError> {
    let mut ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut r, mut w) = stream.into_split();
    let (mut sr, mut sw) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
    Ok(())
}

async fn handle_ssh_direct_tls(mut tls_stream: tokio_rustls::server::TlsStream<TcpStream>, ssh_port: u16, initial_data: Option<Vec<u8>>) -> Result<(), XhttpError> {
    let mut ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    if let Some(data) = initial_data {
        ssh.write_all(&data).await.map_err(|e| Box::new(e) as XhttpError)?;
    }
    let (mut r, mut w) = tokio::io::split(tls_stream);
    let (mut sr, mut sw) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
    Ok(())
}

// --- Funções XHTTP mantidas e ajustadas ---

async fn handle_h2_xhttp(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    status: &str,
    ssh_port: u16,
    client_ip: String,
) -> Result<(), XhttpError> {
    let mut h2_builder = h2::server::Builder::new();
    h2_builder.initial_window_size(2147483647);
    h2_builder.initial_connection_window_size(2147483647);
    let mut h2_conn = h2_builder.handshake(tls_stream).await.map_err(|e| Box::new(e) as XhttpError)?;

    while let Some(result) = h2_conn.accept().await {
        match result {
            Ok((request, respond)) => {
                let method = request.method().clone();
                let path = request.uri().path().to_string();
                let (sid, _) = extract_path_info(&path);
                let st = status.to_string();
                let ip = client_ip.clone();
                match method.as_str() {
                    "GET" => { tokio::spawn(async move { let _ = handle_h2_get(respond, request, &sid, &st, ssh_port, ip).await; }); }
                    "POST" => { tokio::spawn(async move { let _ = handle_h2_post(respond, request, &sid, &st, ip).await; }); }
                    _ => {}
                }
            }
            Err(_) => break,
        }
    }
    Ok(())
}

async fn handle_h2_get(mut respond: h2::server::SendResponse<bytes::Bytes>, _req: http::Request<h2::RecvStream>, sid_in: &str, status: &str, ssh_port: u16, ip: String) -> Result<(), XhttpError> {
    let sid = if sid_in.is_empty() { generate_session_id() } else { sid_in.to_string() };
    let ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut ssh_read, mut ssh_write) = ssh.into_split();
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(1024);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(1024);
    let active = Arc::new(RwLock::new(true));

    SESSIONS.lock().await.insert(sid.clone(), XhttpSession { post_tx, get_tx: get_tx.clone(), active: active.clone() });
    if !ip.is_empty() { IP_SESSIONS.lock().await.insert(ip, sid.clone()); }

    let active_c = active.clone();
    tokio::spawn(async move {
        while let Some(data) = post_rx.recv().await {
            if !*active_c.read().await { break; }
            let _ = ssh_write.write_all(&data).await;
        }
    });

    let get_tx_c = get_tx.clone();
    tokio::spawn(async move {
        let mut b = vec![0u8; 32768];
        while let Ok(Ok(n)) = timeout(Duration::from_secs(600), ssh_read.read(&mut b)).await {
            if n == 0 || get_tx_c.send(b[..n].to_vec()).await.is_err() { break; }
        }
    });

    let resp = http::Response::builder().status(200).header("content-type", "application/octet-stream").header("x-session-id", &sid).header("x-status", status).body(()).unwrap();
    let mut send_stream = respond.send_response(resp, false).map_err(|e| Box::new(e) as XhttpError)?;
    let _ = send_stream.send_data(bytes::Bytes::new(), false);

    while let Ok(Some(data)) = timeout(Duration::from_secs(600), get_rx.recv()).await {
        if send_stream.send_data(bytes::Bytes::from(data), false).is_err() { break; }
    }

    let _ = send_stream.send_trailers(http::HeaderMap::new());
    *active.write().await = false;
    SESSIONS.lock().await.remove(&sid);
    Ok(())
}

async fn handle_h2_post(mut respond: h2::server::SendResponse<bytes::Bytes>, request: http::Request<h2::RecvStream>, sid_in: &str, status: &str, ip: String) -> Result<(), XhttpError> {
    let mut recv = request.into_body();
    let mut sid = sid_in.to_string();
    if sid.is_empty() { if let Some(s) = IP_SESSIONS.lock().await.get(&ip) { sid = s.clone(); } }
    if let Some(session) = SESSIONS.lock().await.get(&sid) {
        let tx = session.post_tx.clone();
        while let Some(chunk) = recv.data().await {
            if let Ok(c) = chunk {
                let len = c.len();
                let _ = tx.send(c.to_vec()).await;
                let _ = recv.flow_control().release_capacity(len);
            } else { break; }
        }
    }
    let resp = http::Response::builder().status(200).header("x-status", status).body(()).unwrap();
    let _ = respond.send_response(resp, true);
    Ok(())
}

async fn handle_http_xhttp_raw(mut stream: TcpStream, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.map_err(|e| Box::new(e) as XhttpError)?;
    let http_str = String::from_utf8_lossy(&buf[..n]);
    if let Some((method, path)) = parse_http_request(&http_str) {
        match method.as_str() {
            "GET" => return handle_xhttp_get_raw(&mut stream, &path, status, ssh_port).await,
            "POST" => return handle_xhttp_post_raw(&mut stream, &buf[..n], &path, status).await,
            _ => {}
        }
    }
    // Fallback para SSH se não for XHTTP reconhecido
    let mut ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    ssh.write_all(&buf[..n]).await.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut r, mut w) = stream.into_split();
    let (mut sr, mut sw) = ssh.into_split();
    let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
    Ok(())
}

async fn handle_xhttp_get_tls(tls: &mut tokio_rustls::server::TlsStream<TcpStream>, path: &str, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut sr, mut sw) = ssh.into_split();
    let (ptx, mut prx) = mpsc::channel::<Vec<u8>>(1024);
    let (gtx, mut grx) = mpsc::channel::<Vec<u8>>(1024);
    let act = Arc::new(RwLock::new(true));
    SESSIONS.lock().await.insert(sid.clone(), XhttpSession { post_tx: ptx, get_tx: gtx.clone(), active: act.clone() });
    let act_c = act.clone();
    tokio::spawn(async move { while let Some(d) = prx.recv().await { if !*act_c.read().await { break; } let _ = sw.write_all(&d).await; } });
    let gtx_c = gtx.clone();
    tokio::spawn(async move { let mut b = vec![0u8; 16384]; while let Ok(Ok(n)) = timeout(Duration::from_secs(600), sr.read(&mut b)).await { if n == 0 || gtx_c.send(b[..n].to_vec()).await.is_err() { break; } } });
    let resp = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Session-ID: {}\r\nX-Status: {}\r\n\r\n", sid, status);
    tls.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
    while let Some(d) = grx.recv().await {
        if tls.write_all(format!("{:x}\r\n", d.len()).as_bytes()).await.is_err() { break; }
        if tls.write_all(&d).await.is_err() { break; }
        if tls.write_all(b"\r\n").await.is_err() { break; }
        let _ = tls.flush().await;
    }
    Ok(())
}

async fn handle_xhttp_get_raw(stream: &mut TcpStream, path: &str, status: &str, ssh_port: u16) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let ssh = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await.map_err(|e| Box::new(e) as XhttpError)?;
    let (mut sr, mut sw) = ssh.into_split();
    let (ptx, mut prx) = mpsc::channel::<Vec<u8>>(1024);
    let (gtx, mut grx) = mpsc::channel::<Vec<u8>>(1024);
    SESSIONS.lock().await.insert(sid.clone(), XhttpSession { post_tx: ptx, get_tx: gtx.clone(), active: Arc::new(RwLock::new(true)) });
    tokio::spawn(async move { while let Some(d) = prx.recv().await { let _ = sw.write_all(&d).await; } });
    let gtx_c = gtx.clone();
    tokio::spawn(async move { let mut b = vec![0u8; 16384]; while let Ok(Ok(n)) = timeout(Duration::from_secs(600), sr.read(&mut b)).await { if n == 0 || gtx_c.send(b[..n].to_vec()).await.is_err() { break; } } });
    let resp = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Session-ID: {}\r\nX-Status: {}\r\n\r\n", sid, status);
    stream.write_all(resp.as_bytes()).await.map_err(|e| Box::new(e) as XhttpError)?;
    while let Some(d) = grx.recv().await {
        if stream.write_all(format!("{:x}\r\n", d.len()).as_bytes()).await.is_err() { break; }
        if stream.write_all(&d).await.is_err() { break; }
        if stream.write_all(b"\r\n").await.is_err() { break; }
        let _ = stream.flush().await;
    }
    Ok(())
}

async fn handle_xhttp_post_tls(tls: &mut tokio_rustls::server::TlsStream<TcpStream>, req: &[u8], path: &str, _: &str) -> Result<(), XhttpError> {
    let (sid, _) = extract_path_info(path);
    let cl = extract_content_length_from_bytes(req).unwrap_or(0);
    let h_end = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let mut body = req[h_end..].to_vec();
    while body.len() < cl {
        let mut b = vec![0u8; cl - body.len()];
        let n = tls.read(&mut b).await.map_err(|e| Box::new(e) as XhttpError)?;
        if n == 0 { break; }
        body.extend_from_slice(&b[..n]);
    }
    if let Some(s) = SESSIONS.lock().await.get(&sid) { let _ = s.post_tx.send(body).await; }
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.map_err(|e| Box::new(e) as XhttpError)?;
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

fn generate_session_id() -> String { format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()) }

fn extract_content_length_from_bytes(data: &[u8]) -> Option<usize> {
    let s = String::from_utf8_lossy(data);
    for l in s.lines() { if l.to_lowercase().starts_with("content-length:") { return l.split(':').nth(1)?.trim().parse().ok(); } }
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
