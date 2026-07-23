use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    println!("[xHTTP] Servico xHTTP SplitHTTP rodando na porta: {}", port);
    println!("[xHTTP] SSH backend: 127.0.0.1:{}", ssh_port);
    println!("[xHTTP] Status: {}", status);
    println!("[xHTTP] Certs: /opt/sdproxy/cert.pem + key.pem");
    println!("[xHTTP] Aguardando conexões...");

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

async fn handle_xhttp_client(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), Error> {
    // Usar PEEK para detectar TLS sem consumir o byte
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
    println!("[xHTTP] Conexão: first_byte=0x{:02x} bytes={}", first_byte, bytes_peeked);

    // Detecta TLS (0x16 = TLS ClientHello)
    if first_byte == 0x16 {
        println!("[xHTTP] TLS detectado, fazendo handshake...");
        return handle_tls_xhttp(stream, status, ssh_port).await;
    }

    // Detecta HTTP (GET, POST, HEAD)
    if first_byte == 0x47 || first_byte == 0x50 || first_byte == 0x48 {
        println!("[xHTTP] HTTP direto detectado");
        return handle_http_xhttp_raw(stream, status, ssh_port).await;
    }

    // Dados raw TCP - tenta tratar como HTTP puro (sem TLS)
    println!("[xHTTP] Dados raw TCP (0x{:02x}), tentando HTTP puro...", first_byte);
    handle_http_xhttp_raw(stream, status, ssh_port).await
}

async fn handle_tls_xhttp(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), Error> {
    println!("[xHTTP] Nova conexão TLS");

    let cert_path = "/opt/sdproxy/cert.pem";
    let key_path = "/opt/sdproxy/key.pem";

    let config = match build_tls_config(cert_path, key_path) {
        Ok(c) => c,
        Err(e) => {
            println!("[xHTTP] Erro TLS config: {}. Verifique /opt/sdproxy/cert.pem e key.pem", e);
            return Ok(());
        }
    };

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            println!("[xHTTP] TLS handshake falhou: {}", e);
            return Ok(());
        }
    };

    println!("[xHTTP] TLS handshake OK");

    // Ler o request HTTP completo
    let (mut tls_read, tls_write) = tokio::io::split(tls_stream);

    // Ler até encontrar \r\n\r\n (fim dos headers)
    let mut http_buf = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let mut end_of_headers = false;
    let mut total_read = 0usize;

    while !end_of_headers && total_read < 65536 {
        match timeout(Duration::from_secs(15), tls_read.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                total_read += n;
                http_buf.extend_from_slice(&chunk[..n]);

                // Procurar \r\n\r\n
                let pos = http_buf.windows(4).position(|w| w == b"\r\n\r\n");
                if let Some(p) = pos {
                    end_of_headers = true;
                    let header_str = String::from_utf8_lossy(&http_buf[..p]);
                    let content_length = extract_content_length(&header_str).unwrap_or(0);
                    let header_end = p + 4;
                    let body_already = total_read - header_end;

                    // Se há body (POST), ler o body completo
                    if content_length > 0 && body_already < content_length {
                        let remaining = content_length - body_already;
                        let mut body_buf = vec![0u8; remaining];
                        let mut body_read = 0;
                        while body_read < remaining {
                            match timeout(Duration::from_secs(30), tls_read.read(&mut body_buf[body_read..])).await {
                                Ok(Ok(n)) if n > 0 => {
                                    body_read += n;
                                }
                                _ => break,
                            }
                        }
                        http_buf.extend_from_slice(&body_buf[..body_read]);
                        println!("[xHTTP] POST body: {} bytes", body_read);
                    }
                }
            }
            _ => {
                println!("[xHTTP] Timeout lendo HTTP request");
                return Ok(());
            }
        }
    }

    let http_str = String::from_utf8_lossy(&http_buf);
    let (method, path) = match parse_http_request(&http_str) {
        Some(m) => m,
        None => {
            println!("[xHTTP] Falha parsear HTTP: {:?}", &http_str[..http_str.len().min(200)]);
            return Ok(());
        }
    };

    println!("[xHTTP] {} {}", method, path);

    let tls_combined = tls_read.unsplit(tls_write);

    match method.as_str() {
        "GET" => handle_xhttp_get(tls_combined, &path, status, ssh_port).await,
        "POST" => handle_xhttp_post(tls_combined, &http_str, &path, status).await,
        other => {
            println!("[xHTTP] Método não suportado: {}", other);
            Ok(())
        }
    }
}

/// Handle dados raw TCP como HTTP puro (sem TLS)
async fn handle_http_xhttp_raw(
    mut stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), Error> {
    // Ler request HTTP completo
    let mut buf = vec![0u8; 32768];
    let n = match timeout(Duration::from_secs(10), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Ok(()),
    };

    let http_str = String::from_utf8_lossy(&buf[..n]);
    println!("[xHTTP RAW] Dados recebidos: {} bytes", n);
    println!("[xHTTP RAW] Content: {:?}", &http_str[..http_str.len().min(300)]);

    // Extrair headers até \r\n\r\n
    let header_end = http_str.find("\r\n\r\n").unwrap_or(0);
    let header_str = if header_end > 0 {
        &http_str[..header_end]
    } else {
        &http_str
    };

    let (method, path) = match parse_http_request(header_str) {
        Some(m) => m,
        None => {
            println!("[xHTTP RAW] Nao eh HTTP valido");
            return Ok(());
        }
    };

    println!("[xHTTP RAW] {} {}", method, path);

    match method.as_str() {
        "GET" => handle_xhttp_get(stream, &path, status, ssh_port).await,
        "POST" => handle_xhttp_post_raw(stream, &http_str[..n], &path, status).await,
        _ => Ok(()),
    }
}

/// xHTTP POST raw (sem TLS) - precisa ler body completo
async fn handle_xhttp_post_raw(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    full_request: &str,
    path: &str,
    status: &str,
) -> Result<(), Error> {
    let (session_id, sequence) = parse_post_path(path);

    println!("[xHTTP POST] Session: {} Seq: {}", session_id, sequence);

    let content_length = extract_content_length(full_request).unwrap_or(0);

    if content_length == 0 {
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Status: {}\r\n\r\n", status);
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Verificar se já temos o body no full_request
    let header_end = full_request.find("\r\n\r\n").map(|p| p + 4).unwrap_or(0);
    let body_in_request = full_request.len() - header_end;

    // Se body ja veio completo
    if body_in_request >= content_length {
        let body = &full_request.as_bytes()[header_end..header_end + content_length];
        send_to_ssh(session_id, body).await;
    } else {
        // Ler o restante do body
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

/// Enviar dados para a sessão SSH
async fn send_to_ssh(session_id: String, data: &[u8]) {
    let sessions = SESSIONS.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        let mut write_guard = session.ssh_write.lock().await;
        let _ = write_guard.write_all(data).await;
        println!("[xHTTP POST] {} bytes -> SSH session {}", data.len(), session_id);
    } else {
        println!("[xHTTP POST] Sessao {} nao encontrada!", session_id);
    }
}

/// xHTTP GET - Criar sessão SSH + Streaming downlink (dados SSH → cliente)
async fn handle_xhttp_get(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    path: &str,
    status: &str,
    ssh_port: u16,
) -> Result<(), Error> {
    let mut session_id = extract_session_id(path);
    println!("[xHTTP GET] Path: {} Session: {}", path, session_id);

    // Se o session_id estiver vazio, geramos um (comum no SocksRevive se o path for /)
    if session_id.is_empty() {
        session_id = format!("revive-{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis());
        println!("[xHTTP GET] Session ID gerado: {}", session_id);
    }

    // Conectar ao SSH backend
    println!("[xHTTP GET] Conectando SSH 127.0.0.1:{}...", ssh_port);
    let ssh_stream = match TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await {
        Ok(s) => s,
        Err(e) => {
            println!("[xHTTP GET] SSH falhou: {}", e);
            let resp = format!("HTTP/1.1 502 Bad Gateway\r\nX-Status: {}\r\nContent-Length: 0\r\n\r\n", status);
            stream.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
    };
    println!("[xHTTP GET] SSH conectado!");

    let (ssh_r, ssh_w) = ssh_stream.into_split();
    let ssh_r = Arc::new(Mutex::new(ssh_r));
    let ssh_w = Arc::new(Mutex::new(ssh_w));

    // Registrar sessão para POSTs
    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), XhttpSession {
            ssh_write: ssh_w,
            ssh_read: ssh_r.clone(),
        });
        println!("[xHTTP GET] Sessão {} registrada", session_id);
    }

    // Enviar response 200 OK sem Content-Length (streaming infinito)
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
    println!("[xHTTP GET] Headers de streaming enviados");

    // Stream direto SSH -> Cliente
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

    // Remover sessão
    {
        let mut sessions = SESSIONS.lock().await;
        sessions.remove(&session_id);
        println!("[xHTTP GET] Sessão {} removida", session_id);
    }

    println!("[xHTTP GET] Fim session {}", session_id);
    Ok(())
}

/// xHTTP POST - Uplink (dados cliente → SSH)
async fn handle_xhttp_post(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    full_request: &str,
    path: &str,
    status: &str,
) -> Result<(), Error> {
    let (session_id, sequence) = parse_post_path(path);

    println!("[xHTTP POST] Session: {} Seq: {}", session_id, sequence);

    let content_length = extract_content_length(full_request).unwrap_or(0);
    println!("[xHTTP POST] Content-Length: {}", content_length);

    if content_length == 0 {
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Status: {}\r\n\r\n", status);
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Ler body completo
    let mut body_buf = vec![0u8; content_length];
    let mut total_read = 0;
    while total_read < content_length {
        match timeout(Duration::from_secs(30), stream.read(&mut body_buf[total_read..])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => total_read += n,
            Ok(Err(e)) => { println!("[xHTTP POST] Erro body: {}", e); break; }
            Err(_) => { println!("[xHTTP POST] Timeout body"); break; }
        }
    }

    println!("[xHTTP POST] Body: {}/{} bytes", total_read, content_length);

    // Enviar ao SSH backend
    let sessions = SESSIONS.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        let mut write_guard = session.ssh_write.lock().await;
        if write_guard.write_all(&body_buf[..total_read]).await.is_err() {
            let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes()).await;
            return Ok(());
        }
        println!("[xHTTP POST] {} bytes → SSH (Seq: {})", total_read, sequence);
    } else {
        println!("[xHTTP POST] Sessão {} não encontrada!", session_id);
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes()).await;
        return Ok(());
    }

    // Responder 200 OK
    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;

    println!("[xHTTP POST] 200 OK enviado");
    Ok(())
}

// === Helpers ===

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
    
    // Se o primeiro componente for 'ssh', o session_id é o segundo
    if parts[0] == "ssh" {
        if parts.len() >= 2 {
            parts[1].to_string()
        } else {
            String::new()
        }
    } else {
        // Caso contrário, o primeiro componente é o session_id
        parts[0].to_string()
    }
}

fn parse_post_path(path: &str) -> (String, String) {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.is_empty() || (parts.len() == 1 && parts[0].is_empty()) {
        return (String::new(), "0".to_string());
    }

    if parts[0] == "ssh" {
        // /ssh/{session_id}/{sequence}
        let sid = if parts.len() >= 2 { parts[1].to_string() } else { String::new() };
        let seq = if parts.len() >= 3 { parts[2].to_string() } else { "0".to_string() };
        (sid, seq)
    } else {
        // /{session_id}/{sequence}
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
