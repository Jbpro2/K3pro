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

    println!("[SDProxy] ═══════════════════════════════════════════");
    println!("[SDProxy]  xHTTP SplitHTTP + SSL TUNNEL");
    println!("[SDProxy] ═══════════════════════════════════════════");
    println!("[SDProxy] Porta: {}", port);
    println!("[SDProxy] SSH Backend: 127.0.0.1:{}", ssh_port);
    println!("[SDProxy] Status: {}", status);
    println!("[SDProxy] Certs: /opt/sdproxy/cert.pem + key.pem");
    println!("[SDProxy] Protocolos: xHTTP | SSL Tunnel | HTTP");
    println!("[SDProxy] ═══════════════════════════════════════════");
    println!("[SDProxy] Aguardando conexões...");

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

/// Handler principal — detecta protocolo e roteia
async fn handle_client(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), Error> {
    let mut peek_buf = [0u8; 3];
    let peek_result = timeout(Duration::from_secs(10), stream.peek(&mut peek_buf)).await;
    let bytes_peeked = match peek_result {
        Ok(Ok(n)) => n,
        _ => return Ok(()),
    };

    if bytes_peeked == 0 {
        return Ok(());
    }

    let first_byte = peek_buf[0];

    if first_byte == 0x16 {
        println!("[SDProxy] TLS detectado (0x{:02x}) — TLS termination", first_byte);
        return handle_tls_connection(stream, status, ssh_port).await;
    }

    if first_byte == 0x47 || first_byte == 0x50 || first_byte == 0x48 || first_byte == 0x43 {
        println!("[SDProxy] HTTP direto detectado (0x{:02x})", first_byte);
        return handle_http_raw(stream, status, ssh_port).await;
    }

    // Dados raw — tratar como SSH/VPN tunnel direto
    println!("[SDProxy] Dados raw (0x{:02x}), tratando como SSH tunnel...", first_byte);
    handle_raw_tunnel(stream, ssh_port).await
}

// ═══════════════════════════════════════════════════════════════
// TLS CONNECTION — TLS termination + roteamento
// ═══════════════════════════════════════════════════════════════
async fn handle_tls_connection(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), Error> {
    println!("[SDProxy][TLS] Handshake...");

    let cert_path = "/opt/sdproxy/cert.pem";
    let key_path = "/opt/sdproxy/key.pem";

    let config = match build_tls_config(cert_path, key_path) {
        Ok(c) => c,
        Err(e) => {
            println!("[SDProxy][TLS] Erro config: {}. Verifique /opt/sdproxy/cert.pem e key.pem", e);
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

    println!("[SDProxy][TLS] Handshake OK");

    // Ler request HTTP dentro do TLS
    let (mut tls_read, tls_write) = tokio::io::split(tls_stream);

    let mut http_buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let mut end_of_headers = false;
    let mut total_read = 0usize;

    while !end_of_headers && total_read < 65536 {
        match timeout(Duration::from_secs(15), tls_read.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                total_read += n;
                http_buf.extend_from_slice(&chunk[..n]);

                let pos = http_buf.windows(4).position(|w| w == b"\r\n\r\n");
                if let Some(p) = pos {
                    end_of_headers = true;
                    let header_str = String::from_utf8_lossy(&http_buf[..p]);
                    let content_length = extract_content_length(&header_str).unwrap_or(0);
                    let header_end = p + 4;
                    let body_already = total_read - header_end;

                    if content_length > 0 && body_already < content_length {
                        let remaining = content_length - body_already;
                        let mut body_buf = vec![0u8; remaining];
                        let mut body_read = 0;
                        while body_read < remaining {
                            match timeout(Duration::from_secs(30), tls_read.read(&mut body_buf[body_read..])).await {
                                Ok(Ok(n)) if n > 0 => { body_read += n; }
                                _ => break,
                            }
                        }
                        http_buf.extend_from_slice(&body_buf[..body_read]);
                    }
                }
            }
            _ => {
                println!("[SDProxy][TLS] Timeout lendo HTTP");
                return Ok(());
            }
        }
    }

    let http_str = String::from_utf8_lossy(&http_buf);
    let (method, path) = match parse_http_request(&http_str) {
        Some(m) => m,
        None => {
            println!("[SDProxy][TLS] Falha parsear HTTP: {:?}", &http_str[..http_str.len().min(200)]);
            return Ok(());
        }
    };

    println!("[SDProxy][TLS] {} {}", method, path);

    let tls_combined = tls_read.unsplit(tls_write);

    // Rotear: xHTTP SplitHTTP ou SSL Tunnel
    if is_xhttp_path(&path) {
        println!("[SDProxy][TLS] → xHTTP SplitHTTP");
        match method.as_str() {
            "GET" => handle_xhttp_get(tls_combined, &path, status, ssh_port).await,
            "POST" => handle_xhttp_post(tls_combined, &http_str, &path, status).await,
            other => {
                println!("[SDProxy][TLS] Método não suportado: {}", other);
                Ok(())
            }
        }
    } else {
        println!("[SDProxy][TLS] → SSL TUNNEL");
        handle_ssl_tunnel_after_tls(tls_combined, &http_str, status, ssh_port).await
    }
}

/// Verifica se o path é de xHTTP
fn is_xhttp_path(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    // /ssh/... é sempre xHTTP
    if p.starts_with("ssh/") || p == "ssh" {
        return true;
    }
    // Path com session_id (ex: /revive-xxx/0 ou /abc123)
    let parts: Vec<&str> = p.split('/').collect();
    if parts.len() >= 1 && !parts[0].is_empty() && parts.len() <= 2 {
        // Se tem pelo menos 2 componentes (session_id + seq), é xHTTP
        if parts.len() >= 2 {
            return true;
        }
        // Se tem 1 componente e parece um session_id (não é path comum)
        // Qualquer path que não é vazio é tratado como xHTTP para compatibilidade
        // (o antigo comportamento tratava "/" como xHTTP com session_id gerado)
        if !parts[0].contains('.') && !parts[0].contains('?') && parts[0].len() > 3 {
            return true;
        }
    }
    false
}

// ═══════════════════════════════════════════════════════════════
// SSL TUNNEL (após TLS termination)
// Injector: TLS handshake → HTTP GET → 200 OK → SSH bridge
// ═══════════════════════════════════════════════════════════════
async fn handle_ssl_tunnel_after_tls(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    _http_request: &str,
    status: &str,
    ssh_port: u16,
) -> Result<(), Error> {
    println!("[SDProxy][SSL-TUNNEL] Enviando HTTP/1.1 200 OK...");

    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Length: 0\r\n\
         Connection: keep-alive\r\n\
         X-Status: {}\r\n\
         \r\n",
        status
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    println!("[SDProxy][SSL-TUNNEL] 200 OK enviado, conectando SSH...");

    let ssh_addr = format!("127.0.0.1:{}", ssh_port);
    match TcpStream::connect(&ssh_addr).await {
        Ok(mut ssh_stream) => {
            println!("[SDProxy][SSL-TUNNEL] SSH:{} conectado", ssh_port);
            let _ = copy_bidirectional(&mut stream, &mut ssh_stream).await;
            println!("[SDProxy][SSL-TUNNEL] Tunnel encerrado");
            Ok(())
        }
        Err(e) => {
            println!("[SDProxy][SSL-TUNNEL] SSH falhou: {}, tentando VPN:1194...", e);
            match TcpStream::connect("127.0.0.1:1194").await {
                Ok(mut vpn_stream) => {
                    let _ = copy_bidirectional(&mut stream, &mut vpn_stream).await;
                    println!("[SDProxy][SSL-TUNNEL] Tunnel VPN encerrado");
                    Ok(())
                }
                Err(e2) => {
                    println!("[SDProxy][SSL-TUNNEL] Ambos falharam: {} / {}", e, e2);
                    Ok(())
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// HTTP RAW — xHTTP ou SSL Tunnel via HTTP
// ═══════════════════════════════════════════════════════════════
async fn handle_http_raw(
    mut stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), Error> {
    let mut buf = vec![0u8; 32768];
    let n = match timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Ok(()),
    };

    let http_str = String::from_utf8_lossy(&buf[..n]);

    let header_end = http_str.find("\r\n\r\n").unwrap_or(0);
    let header_str = if header_end > 0 {
        &http_str[..header_end]
    } else {
        &http_str
    };

    let (method, path) = match parse_http_request(header_str) {
        Some(m) => m,
        None => {
            // Não é HTTP válido — raw tunnel direto
            println!("[SDProxy][RAW] Dados raw, tunnel SSH direto...");
            return handle_raw_tunnel_with_data(buf[..n].to_vec(), stream, ssh_port).await;
        }
    };

    println!("[SDProxy][RAW] {} {}", method, path);

    if is_xhttp_path(&path) {
        match method.as_str() {
            "GET" => handle_xhttp_get(stream, &path, status, ssh_port).await,
            "POST" => handle_xhttp_post_raw(stream, &http_str[..n], &path, status).await,
            _ => Ok(()),
        }
    } else {
        // SSL Tunnel via HTTP
        println!("[SDProxy][RAW] → SSL TUNNEL (HTTP)");
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Length: 0\r\n\
             Connection: keep-alive\r\n\
             X-Status: {}\r\n\
             \r\n",
            status
        );
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;

        let ssh_addr = format!("127.0.0.1:{}", ssh_port);
        match TcpStream::connect(&ssh_addr).await {
            Ok(mut ssh_stream) => {
                let _ = copy_bidirectional(&mut stream, &mut ssh_stream).await;
                Ok(())
            }
            Err(e) => {
                match TcpStream::connect("127.0.0.1:1194").await {
                    Ok(mut vpn_stream) => {
                        let _ = copy_bidirectional(&mut stream, &mut vpn_stream).await;
                        Ok(())
                    }
                    Err(e2) => {
                        println!("[SDProxy][RAW-TUNNEL] Ambos falharam: {} / {}", e, e2);
                        Ok(())
                    }
                }
            }
        }
    }
}

/// Raw tunnel com dados iniciais
async fn handle_raw_tunnel_with_data(
    initial_data: Vec<u8>,
    mut stream: TcpStream,
    ssh_port: u16,
) -> Result<(), Error> {
    let ssh_addr = format!("127.0.0.1:{}", ssh_port);
    match TcpStream::connect(&ssh_addr).await {
        Ok(mut ssh_stream) => {
            ssh_stream.write_all(&initial_data).await?;
            ssh_stream.flush().await?;
            let _ = copy_bidirectional(&mut stream, &mut ssh_stream).await;
            Ok(())
        }
        Err(e) => {
            match TcpStream::connect("127.0.0.1:1194").await {
                Ok(mut vpn_stream) => {
                    vpn_stream.write_all(&initial_data).await?;
                    vpn_stream.flush().await?;
                    let _ = copy_bidirectional(&mut stream, &mut vpn_stream).await;
                    Ok(())
                }
                Err(e2) => {
                    println!("[SDProxy][RAW] Ambos falharam: {} / {}", e, e2);
                    Ok(())
                }
            }
        }
    }
}

/// Raw tunnel direto
async fn handle_raw_tunnel(
    mut stream: TcpStream,
    ssh_port: u16,
) -> Result<(), Error> {
    let ssh_addr = format!("127.0.0.1:{}", ssh_port);
    match TcpStream::connect(&ssh_addr).await {
        Ok(mut ssh_stream) => {
            let _ = copy_bidirectional(&mut stream, &mut ssh_stream).await;
            Ok(())
        }
        Err(e) => {
            match TcpStream::connect("127.0.0.1:1194").await {
                Ok(mut vpn_stream) => {
                    let _ = copy_bidirectional(&mut stream, &mut vpn_stream).await;
                    Ok(())
                }
                Err(e2) => {
                    println!("[SDProxy][RAW] Ambos falharam: {} / {}", e, e2);
                    Ok(())
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// xHTTP SplitHTTP — GET (downlink)
// ═══════════════════════════════════════════════════════════════
async fn handle_xhttp_get(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    path: &str,
    status: &str,
    ssh_port: u16,
) -> Result<(), Error> {
    let mut session_id = extract_session_id(path);
    println!("[SDProxy][xHTTP-GET] Path: {} Session: {}", path, session_id);

    if session_id.is_empty() {
        session_id = format!("revive-{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis());
    }

    println!("[SDProxy][xHTTP-GET] Conectando SSH 127.0.0.1:{}...", ssh_port);
    let ssh_stream = match TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
        Ok(s) => s,
        Err(e) => {
            println!("[SDProxy][xHTTP-GET] SSH falhou: {}", e);
            let resp = format!("HTTP/1.1 502 Bad Gateway\r\nX-Status: {}\r\nContent-Length: 0\r\n\r\n", status);
            stream.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
    };
    println!("[SDProxy][xHTTP-GET] SSH conectado!");

    let (ssh_r, ssh_w) = ssh_stream.into_split();
    let ssh_r = Arc::new(Mutex::new(ssh_r));
    let ssh_w = Arc::new(Mutex::new(ssh_w));

    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), XhttpSession {
            ssh_write: ssh_w,
            ssh_read: ssh_r.clone(),
        });
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Cache-Control: no-cache, no-store, must-revalidate\r\n\
         Pragma: no-cache\r\n\
         Expires: 0\r\n\
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
        match timeout(Duration::from_secs(60), read_guard.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if stream.write_all(&buffer[..n]).await.is_err() { break; }
                let _ = stream.flush().await;
            }
            _ => break,
        }
    }

    {
        let mut sessions = SESSIONS.lock().await;
        sessions.remove(&session_id);
    }

    println!("[SDProxy][xHTTP-GET] Fim session {}", session_id);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// xHTTP SplitHTTP — POST (uplink)
// ═══════════════════════════════════════════════════════════════
async fn handle_xhttp_post(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    full_request: &str,
    path: &str,
    status: &str,
) -> Result<(), Error> {
    let (session_id, sequence) = parse_post_path(path);

    println!("[SDProxy][xHTTP-POST] Session: {} Seq: {}", session_id, sequence);

    let content_length = extract_content_length(full_request).unwrap_or(0);

    if content_length == 0 {
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Status: {}\r\n\r\n", status);
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let mut body_buf = vec![0u8; content_length];
    let mut total_read = 0;
    while total_read < content_length {
        match timeout(Duration::from_secs(30), stream.read(&mut body_buf[total_read..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => total_read += n,
            Ok(Err(e)) => { println!("[SDProxy][xHTTP-POST] Erro: {}", e); break; }
            Err(_) => { println!("[SDProxy][xHTTP-POST] Timeout"); break; }
        }
    }

    let sessions = SESSIONS.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        let mut write_guard = session.ssh_write.lock().await;
        if write_guard.write_all(&body_buf[..total_read]).await.is_err() {
            let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes()).await;
            return Ok(());
        }
    } else {
        println!("[SDProxy][xHTTP-POST] Sessão {} não encontrada!", session_id);
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        return Ok(());
    }

    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// xHTTP POST raw (sem TLS)
async fn handle_xhttp_post_raw(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    full_request: &str,
    path: &str,
    status: &str,
) -> Result<(), Error> {
    let (session_id, _sequence) = parse_post_path(path);

    let content_length = extract_content_length(full_request).unwrap_or(0);

    if content_length == 0 {
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Status: {}\r\n\r\n", status);
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let header_end = full_request.find("\r\n\r\n").map(|p| p + 4).unwrap_or(0);
    let body_in_request = full_request.len() - header_end;

    if body_in_request >= content_length {
        let body = &full_request.as_bytes()[header_end..header_end + content_length];
        send_to_ssh(session_id, body).await;
    } else {
        let remaining = content_length - body_in_request;
        let mut body_buf = vec![0u8; remaining];
        let mut body_read = 0;
        while body_read < remaining {
            match timeout(Duration::from_secs(30), stream.read(&mut body_buf[body_read..])).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => body_read += n,
                _ => break,
            }
        }
        let mut full_body = full_request.as_bytes()[header_end..].to_vec();
        full_body.extend_from_slice(&body_buf[..body_read]);
        send_to_ssh(session_id, &full_body[..content_length.min(full_body.len())]).await;
    }

    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Status: {}\r\n\r\n", status);
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_to_ssh(session_id: String, data: &[u8]) {
    let sessions = SESSIONS.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        let mut write_guard = session.ssh_write.lock().await;
        let _ = write_guard.write_all(data).await;
    }
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

fn parse_http_request(data: &str) -> Option<(String, String)> {
    let first_line = data.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

fn extract_session_id(path: &str) -> String {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.is_empty() || (parts.len() == 1 && parts[0].is_empty()) {
        return String::new();
    }
    if parts[0] == "ssh" {
        if parts.len() >= 2 { parts[1].to_string() } else { String::new() }
    } else {
        parts[0].to_string()
    }
}

fn parse_post_path(path: &str) -> (String, String) {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.is_empty() || (parts.len() == 1 && parts[0].is_empty()) {
        return (String::new(), "0".to_string());
    }
    if parts[0] == "ssh" {
        let sid = if parts.len() >= 2 { parts[1].to_string() } else { String::new() };
        let seq = if parts.len() >= 3 { parts[2].to_string() } else { "0".to_string() };
        (sid, seq)
    } else {
        let sid = parts[0].to_string();
        let seq = if parts.len() >= 2 { parts[1].to_string() } else { "0".to_string() };
        (sid, seq)
    }
}

fn extract_content_length(data: &str) -> Option<usize> {
    for line in data.lines() {
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

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.into_iter().next().unwrap())
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;

    Ok(config)
}

fn get_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 443;
    for i in 1..args.len() {
        if args[i] == "--port" || args[i] == "-p" {
            if i + 1 < args.len() {
                port = args[i + 1].parse().unwrap_or(443);
            }
        }
    }
    port
}

fn get_status() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut status = String::from("@SDProxy");
    for i in 1..args.len() {
        if args[i] == "--status" || args[i] == "-s" {
            if i + 1 < args.len() {
                status = args[i + 1].clone();
            }
        }
    }
    status
}

fn get_ssh_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 22;
    for i in 1..args.len() {
        if args[i] == "--ssh-port" {
            if i + 1 < args.len() {
                port = args[i + 1].parse().unwrap_or(22);
            }
        }
    }
    port
}
