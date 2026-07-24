use std::collections::HashMap;

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{timeout, Duration};

use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

/// Sessão xHTTP ativa com canais para comunicação GET<->POST<->SSH
#[allow(dead_code)]
struct XhttpSession {
    post_tx: mpsc::Sender<Vec<u8>>,
    get_tx: mpsc::Sender<Vec<u8>>,
    active: Arc<RwLock<bool>>,
}

/// Tipo de erro simplificado para xHTTP
type XhttpError = Box<dyn std::error::Error + Send + Sync>;

static SESSIONS: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, XhttpSession>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[tokio::main]
async fn main() -> Result<(), XhttpError> {
    let port = get_port();
    let status = get_status();
    let ssh_port = get_ssh_port();

    println!("[BDRProxy] xHTTP SplitHTTP v3.0.0 (Universal Fallback)");
    println!("[xHTTP] Servico xHTTP SplitHTTP rodando na porta: {}", port);
    println!("[xHTTP] SSH backend: 127.0.0.1:{}", ssh_port);
    println!("[xHTTP] Status: {}", status);
    println!("[xHTTP] Certs: /opt/sdproxy/cert.pem + key.pem");
    println!("[xHTTP] Protocolos: HTTP/1.1 + HTTP/2 (h2)");
    println!("[xHTTP] Aguardando conexoes...");


    let listener = TcpListener::bind(format!("[::]:{}", port)).await.map_err(|e| -> XhttpError { Box::new(e) })?;
    let status_arc = Arc::new(status);

    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                // Otimização de socket
                let _ = client_stream.set_nodelay(true);
                println!("[xHTTP] Nova conexão de: {}", addr);
                let status = status_arc.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_xhttp_client(client_stream, &status, ssh_port).await {
                        println!("[xHTTP] Finalizado para {}: {}", addr, e);
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
    let mut peek_buf = [0u8; 3];
    let peek_result = timeout(Duration::from_secs(10), stream.peek(&mut peek_buf)).await;
    let bytes_peeked = match peek_result {
        Ok(Ok(n)) => n,
        _ => return Ok(()),
    };

    let first_byte = peek_buf[0];
    println!("[xHTTP] Conexão: first_byte=0x{:02x} bytes={}", first_byte, bytes_peeked);

    if first_byte == 0x16 {
        println!("[xHTTP] TLS detectado, fazendo handshake...");
        return handle_tls_xhttp(stream, status, ssh_port).await;
    }

    if first_byte == 0x47 || first_byte == 0x50 || first_byte == 0x48 {
        println!("[xHTTP] HTTP direto detectado");
        return handle_http_xhttp_raw(stream, status, ssh_port).await;
    }

    println!("[xHTTP] Dados raw TCP (0x{:02x}), tentando HTTP puro...", first_byte);
    handle_http_xhttp_raw(stream, status, ssh_port).await
}

async fn handle_tls_xhttp(
    stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    let cert_path = "/opt/sdproxy/cert.pem";
    let key_path = "/opt/sdproxy/key.pem";

    let mut config = match build_tls_config(cert_path, key_path) {
        Ok(c) => c,
        Err(e) => {
            println!("[xHTTP] Erro TLS config: {}", e);
            return Ok(());
        }
    };

    // Aceitar h2 e http/1.1 via ALPN
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            println!("[xHTTP] TLS handshake falhou: {}", e);
            return Ok(());
        }
    };

    // Verificar ALPN negociado
    let alpn = tls_stream.get_ref().1.alpn_protocol();
    match alpn {
        Some(b"h2") => {
            println!("[xHTTP] ALPN: h2 (HTTP/2)");
            return handle_h2_xhttp(tls_stream, status, ssh_port).await;
        }
        Some(b"http/1.1") => {
            println!("[xHTTP] ALPN: http/1.1");
            return handle_http1_tls(tls_stream, status, ssh_port).await;
        }
        other => {
            let alpn_str = other.map(|p| String::from_utf8_lossy(p).to_string()).unwrap_or_else(|| "None".to_string());
            println!("[xHTTP] ALPN não negociado: {}, tentando HTTP/1.1...", alpn_str);
            return handle_http1_tls(tls_stream, status, ssh_port).await;
        }
    }
}

/// HTTP/2 handler usando crate h2
async fn handle_h2_xhttp(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    println!("[xHTTP h2] Iniciando handshake HTTP/2...");

    // Handshake HTTP/2 com limites aumentados para evitar travamentos
    let mut h2_builder = h2::server::Builder::new();
    h2_builder.initial_window_size(2147483647); // Máximo (2GB)
    h2_builder.initial_connection_window_size(2147483647);
    h2_builder.max_frame_size(16384);
    
    let mut h2_conn = match h2_builder.handshake(tls_stream).await {
        Ok(c) => c,
        Err(e) => {
            println!("[xHTTP h2] Handshake falhou: {}", e);
            return Ok(());
        }
    };

    println!("[xHTTP h2] Handshake HTTP/2 OK");

    // Acceptar streams HTTP/2
    while let Some(result) = h2_conn.accept().await {
        match result {
            Ok((request, mut respond)) => {
                let method = request.method().clone();
                let path = request.uri().path().to_string();
                let session_id = extract_session_id_h2(&path);
                let status = status.to_string();

                println!("[xHTTP h2] Stream: {} {} session={}", method, path, session_id);

                match method.as_str() {
                    "GET" => {
                        tokio::spawn(async move {
                            if let Err(e) = handle_h2_get(respond, request, &session_id, &status, ssh_port).await {
                                println!("[xHTTP h2 GET] Erro: {}", e);
                            }
                        });
                    }
                    "POST" => {
                        tokio::spawn(async move {
                            if let Err(e) = handle_h2_post(respond, request, &session_id, &status).await {
                                println!("[xHTTP h2 POST] Erro: {}", e);
                            }
                        });
                    }
                    _ => {
                        println!("[xHTTP h2] Metodo nao suportado: {}", method);
                        let resp: http::Response<()> = http::Response::builder()
                            .status(200)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(resp, true);
                    }
                }
            }
            Err(e) => {
                println!("[xHTTP h2] Erro aceitar stream: {}", e);
                break;
            }
        }
    }

    println!("[xHTTP h2] Conexão fechada");
    Ok(())
}

/// Handle GET HTTP/2 - cria SSH e faz streaming
async fn handle_h2_get(
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    _request: http::Request<h2::RecvStream>,
    session_id: &str,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    let sid = if session_id.is_empty() {
        generate_session_id()
    } else {
        session_id.to_string()
    };

    println!("[xHTTP h2 GET] Session: {}", sid);

    // Conectar ao SSH
    let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
    println!("[xHTTP h2 GET] SSH conectado!");

    let (mut ssh_read, mut ssh_write) = ssh_stream.into_split();

    // Criar canais
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(256);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(256);
    let active = Arc::new(RwLock::new(true));

    // Registrar sessão
    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(sid.clone(), XhttpSession {
            post_tx,
            get_tx: get_tx.clone(),
            active: active.clone(),
        });
        println!("[xHTTP h2 GET] Sessão {} registrada", sid);
    }

    // Task: SSH write
    let active_write = active.clone();
    tokio::spawn(async move {
        while let Some(data) = post_rx.recv().await {
            if !*active_write.read().await {
                break;
            }
            if ssh_write.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    // Task: SSH read -> canal
    let get_tx_read = get_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match timeout(Duration::from_secs(60), ssh_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    let data = buf[..n].to_vec();
                    if get_tx_read.send(data).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    });

    // Construir response HTTP/2 com streaming e headers de compatibilidade CDN
    let response: http::Response<()> = http::Response::builder()
        .status(200)
        .header("content-type", "application/octet-stream")
        .header("cache-control", "no-cache, no-store, must-revalidate, proxy-revalidate")
        .header("pragma", "no-cache")
        .header("expires", "0")
        .header("connection", "keep-alive")
        .header("x-accel-buffering", "no") // Importante para CDNs
        .header("x-session-id", &sid)
        .header("x-status", status)
        .body(())
        .unwrap();

    // Enviar response com end_of_stream=false (streaming)
    let mut send_stream = match respond.send_response(response, false) {
        Ok(s) => s,
        Err(e) => {
            println!("[xHTTP h2 GET] Erro send_response: {}", e);
            *active.write().await = false;
            return Ok(());
        }
    };

    println!("[xHTTP h2 GET] Streaming iniciado para session {}", sid);

    // Kickstart: envia um frame vazio imediatamente para "acordar" o download no cliente
    let _ = send_stream.send_data(bytes::Bytes::new(), false);

    // Stream dados do canal GET para o cliente com Keep-Alive
    loop {
        // Espera dados do SSH ou envia um ping se ficar muito tempo parado
        match timeout(Duration::from_secs(30), get_rx.recv()).await {
            Ok(Some(data)) => {
                let chunk = bytes::Bytes::from(data);
                if send_stream.send_data(chunk, false).is_err() {
                    println!("[xHTTP h2 GET] Erro send_data (stream closed)");
                    break;
                }
            }
            Ok(None) => {
                println!("[xHTTP h2 GET] Canal fechado (SSH EOF)");
                break;
            }
            Err(_) => {
                // Envia um frame vazio como Keep-Alive para manter a CDN/DTUNNEL ativos
                // Alguns clientes SplitHTTP ignoram frames vazios, mas eles mantêm o stream h2 aberto
                if send_stream.send_data(bytes::Bytes::new(), false).is_err() {
                    println!("[xHTTP h2 GET] Erro send_data (Keep-Alive failed)");
                    break;
                }
            }
        }
    }

    // Finalizar stream - enviar trailer vazio
    let trailers = http::HeaderMap::new();
    let _ = send_stream.send_trailers(trailers);

    // Desativar sessão
    *active.write().await = false;
    {
        let mut sessions = SESSIONS.lock().await;
        sessions.remove(&sid);
        println!("[xHTTP h2 GET] Sessão {} removida", sid);
    }

    Ok(())
}

/// Handle POST HTTP/2 - recebe dados e envia para SSH via canal
async fn handle_h2_post(
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    request: http::Request<h2::RecvStream>,
    session_id: &str,
    status: &str,
) -> Result<(), XhttpError> {
    println!("[xHTTP h2 POST] Session: {}", session_id);

    let content_length = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    println!("[xHTTP h2 POST] Content-Length: {}", content_length);

    if content_length == 0 {
        let response: http::Response<()> = http::Response::builder()
            .status(200)
            .header("x-status", status)
            .body(())
            .unwrap();
        let _ = respond.send_response(response, true);
        return Ok(());
    }

    // Ler body do POST
    let mut body = Vec::with_capacity(content_length);
    let mut recv_stream = request.into_body();

    while let Some(chunk) = recv_stream.data().await {
        match chunk {
            Ok(c) => {
                body.extend_from_slice(&c);
                if body.len() >= content_length {
                    break;
                }
            }
            Err(e) => {
                println!("[xHTTP h2 POST] Erro lendo body: {}", e);
                break;
            }
        }
    }

    body.truncate(content_length);
    println!("[xHTTP h2 POST] {} bytes recebidos", body.len());

    // Enviar para SSH via canal
    let sessions = SESSIONS.lock().await;
    if let Some(session) = sessions.get(session_id) {
        if session.post_tx.send(body).await.is_err() {
            println!("[xHTTP h2 POST] Canal POST fechado para {}", session_id);
            let response: http::Response<()> = http::Response::builder()
                .status(503)
                .body(())
                .unwrap();
            let _ = respond.send_response(response, true);
            return Ok(());
        }
    } else {
        println!("[xHTTP h2 POST] Sessão {} não encontrada!", session_id);
        let response: http::Response<()> = http::Response::builder()
            .status(404)
            .body(())
            .unwrap();
        let _ = respond.send_response(response, true);
        return Ok(());
    }

    // Responder 200 OK
    let response: http::Response<()> = http::Response::builder()
        .status(200)
        .header("content-length", "0")
        .header("x-status", status)
        .body(())
        .unwrap();

    let _ = respond.send_response(response, true);
    println!("[xHTTP h2 POST] 200 OK enviado");

    Ok(())
}

/// HTTP/1.1 sobre TLS handler
async fn handle_http1_tls(
    mut tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    println!("[xHTTP h1] Lendo request HTTP/1.1...");

    // Ler request HTTP/1.1
    let mut read_buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    let mut end_of_headers = false;
    let mut total_read = 0usize;

    while !end_of_headers && total_read < 65536 {
        match timeout(Duration::from_secs(15), tls_stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => {
                total_read += n;
                read_buf.extend_from_slice(&chunk[..n]);
                if read_buf.windows(4).position(|w| w == b"\r\n\r\n").is_some() {
                    end_of_headers = true;
                }
            }
            _ => {
                println!("[xHTTP h1] Timeout lendo request");
                return Ok(());
            }
        }
    }

    let header_end_pos = read_buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
    let http_str: String = String::from_utf8_lossy(&read_buf[..header_end_pos]).to_string();
    let content_length = extract_content_length_from_bytes(&read_buf[..header_end_pos + 4]).unwrap_or(0);
    let body_already = total_read - (header_end_pos + 4);

    // Ler body se POST
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
        read_buf.extend_from_slice(&body_buf[..body_read]);
    }

    let (method, path) = match parse_http_request(&http_str) {
        Some(m) => m,
        None => {
            println!("[xHTTP h1] Falha parsear HTTP");
            return Ok(());
        }
    };

    println!("[xHTTP h1] {} {}", method, path);

    match method.as_str() {
        "GET" => handle_xhttp_get_tls(&mut tls_stream, &path, status, ssh_port).await,
        "POST" => handle_xhttp_post_tls(&mut tls_stream, &read_buf, &path, status).await,
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

/// HTTP/1.1 raw (sem TLS)
async fn handle_http_xhttp_raw(
    mut stream: TcpStream,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
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
            println!("[xHTTP RAW] Não é HTTP válido");
            return Ok(());
        }
    };

    println!("[xHTTP RAW] {} {}", method, path);

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

/// xHTTP GET via TLS (HTTP/1.1) - Abre SSH e faz streaming
async fn handle_xhttp_get_tls(
    tls_stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    path: &str,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    let mut session_id = extract_session_id(path);
    if session_id.is_empty() {
        session_id = generate_session_id();
    }
    println!("[xHTTP GET TLS] Session: {}", session_id);

    let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
    println!("[xHTTP GET TLS] SSH conectado!");

    let (mut ssh_read, mut ssh_write) = ssh_stream.into_split();
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(256);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(256);
    let active = Arc::new(RwLock::new(true));

    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), XhttpSession {
            post_tx,
            get_tx: get_tx.clone(),
            active: active.clone(),
        });
    }

    let active_write = active.clone();
    tokio::spawn(async move {
        while let Some(data) = post_rx.recv().await {
            if !*active_write.read().await { break; }
            if ssh_write.write_all(&data).await.is_err() { break; }
        }
    });

    let get_tx_read = get_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match timeout(Duration::from_secs(60), ssh_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    let data = buf[..n].to_vec();
                    if get_tx_read.send(data).await.is_err() { break; }
                }
                _ => break,
            }
        }
    });

    // Handshake ultra-compatível
    let h101 = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: DTUNNEL\r\n\r\n";
    let _ = tls_stream.write_all(h101.as_bytes()).await;
    let _ = tls_stream.flush().await;

    let h200 = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Connection: keep-alive\r\n\
         X-Session-ID: {}\r\n\
         X-Status: {}\r\n\r\n",
        session_id, status
    );
    let _ = tls_stream.write_all(h200.as_bytes()).await;
    let _ = tls_stream.flush().await;
    println!("[xHTTP GET TLS] Handshake enviado para {}", session_id);

    // Stream com Keep-Alive para h1
    loop {
        match timeout(Duration::from_secs(30), get_rx.recv()).await {
            Ok(Some(data)) => {
                if tls_stream.write_all(&data).await.is_err() { break; }
                let _ = tls_stream.flush().await;
            }
            Ok(None) => break,
            Err(_) => {
                // Keep-Alive: envia um frame vazio/flush para manter conexão ativa
                let _ = tls_stream.flush().await;
            }
        }
    }

    *active.write().await = false;
    {
        let mut sessions = SESSIONS.lock().await;
        sessions.remove(&session_id);
    }
    Ok(())
}

/// xHTTP GET raw (sem TLS, HTTP/1.1)
async fn handle_xhttp_get_raw(
    mut stream: impl AsyncReadExt + AsyncWriteExt + Unpin,
    path: &str,
    status: &str,
    ssh_port: u16,
) -> Result<(), XhttpError> {
    let mut session_id = extract_session_id(path);
    if session_id.is_empty() { session_id = generate_session_id(); }

    let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", ssh_port)).await?;
    let (mut ssh_read, mut ssh_write) = ssh_stream.into_split();
    let (post_tx, mut post_rx) = mpsc::channel::<Vec<u8>>(256);
    let (get_tx, mut get_rx) = mpsc::channel::<Vec<u8>>(256);
    let active = Arc::new(RwLock::new(true));

    {
        let mut sessions = SESSIONS.lock().await;
        sessions.insert(session_id.clone(), XhttpSession {
            post_tx,
            get_tx: get_tx.clone(),
            active: active.clone(),
        });
    }

    tokio::spawn(async move {
        while let Some(data) = post_rx.recv().await {
            if ssh_write.write_all(&data).await.is_err() { break; }
        }
    });

    let get_tx_read = get_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match timeout(Duration::from_secs(60), ssh_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    let data = buf[..n].to_vec();
                    if get_tx_read.send(data).await.is_err() { break; }
                }
                _ => break,
            }
        }
    });

    // Handshake simplificado para máxima compatibilidade
    let full_handshake = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Connection: upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Accept: DTUNNEL\r\n\r\n\
         HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Cache-Control: no-cache, no-store, must-revalidate, proxy-revalidate\r\n\
         Pragma: no-cache\r\n\
         Expires: 0\r\n\
         Connection: keep-alive\r\n\
         X-Accel-Buffering: no\r\n\
         X-Session-ID: {}\r\n\
         X-Status: {}\r\n\r\n",
        session_id, status
    );
    let _ = stream.write_all(full_handshake.as_bytes()).await;
    let _ = stream.flush().await;

    loop {
        match timeout(Duration::from_secs(30), get_rx.recv()).await {
            Ok(Some(data)) => {
                if stream.write_all(&data).await.is_err() { break; }
                let _ = stream.flush().await;
            }
            Ok(None) => break,
            Err(_) => {
                let _ = stream.flush().await;
            }
        }
    }

    *active.write().await = false;
    {
        let mut sessions = SESSIONS.lock().await;
        sessions.remove(&session_id);
    }
    Ok(())
}

/// xHTTP POST via TLS (HTTP/1.1)
async fn handle_xhttp_post_tls(
    tls_stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    full_request: &[u8],
    path: &str,
    status: &str,
) -> Result<(), XhttpError> {
    let session_id = extract_session_id(path);
    println!("[xHTTP POST TLS] Session: {} (path: {})", session_id, path);

    let content_length = extract_content_length_from_bytes(full_request).unwrap_or(0);
    if content_length == 0 {
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Status: {}\r\n\r\n", status);
        tls_stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let header_end = full_request.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let body_in_request = full_request.len() - header_end;

    let sessions = SESSIONS.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        let body = if body_in_request >= content_length {
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
            body[..content_length].to_vec()
        };

        if session.post_tx.send(body).await.is_err() {
            println!("[xHTTP POST TLS] Canal POST fechado");
        }
    } else {
        println!("[xHTTP POST TLS] Sessão {} não encontrada! Fallback para Túnel Direto...", session_id);
        let resp = format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: DTUNNEL\r\n\r\nHTTP/1.1 200 OK\r\nConnection: keep-alive\r\nX-Status: {}\r\n\r\n", status);
        tls_stream.write_all(resp.as_bytes()).await?;
        let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", 22)).await?;
        let (mut r, mut w) = tokio::io::split(tls_stream);
        let (mut sr, mut sw) = ssh_stream.into_split();
        let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
        return Ok(());
    }

    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    tls_stream.write_all(resp.as_bytes()).await?;
    tls_stream.flush().await?;
    Ok(())
}

/// xHTTP POST raw (sem TLS)
async fn handle_xhttp_post_raw<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    full_request: &[u8],
    path: &str,
    status: &str,
) -> Result<(), XhttpError> {
    let session_id = extract_session_id(path);
    println!("[xHTTP POST RAW] Session: {} (path: {})", session_id, path);

    let content_length = extract_content_length_from_bytes(full_request).unwrap_or(0);
    if content_length == 0 {
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Status: {}\r\n\r\n", status);
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let header_end = full_request.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 4;
    let body_in_request = full_request.len() - header_end;

    let sessions = SESSIONS.lock().await;
    if let Some(session) = sessions.get(&session_id) {
        let body = if body_in_request >= content_length {
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
            body[..content_length].to_vec()
        };

        if session.post_tx.send(body).await.is_err() {
            println!("[xHTTP POST RAW] Canal POST fechado");
        }
    } else {
        println!("[xHTTP POST RAW] Sessão {} não encontrada! Fallback para Túnel Direto...", session_id);
        let resp = format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: DTUNNEL\r\n\r\nHTTP/1.1 200 OK\r\nConnection: keep-alive\r\nX-Status: {}\r\n\r\n", status);
        stream.write_all(resp.as_bytes()).await?;
        let ssh_stream = TcpStream::connect(format!("127.0.0.1:{}", 22)).await?;
        let (mut r, mut w) = tokio::io::split(stream);
        let (mut sr, mut sw) = ssh_stream.into_split();
        let _ = tokio::join!(tokio::io::copy(&mut r, &mut sw), tokio::io::copy(&mut sr, &mut w));
        return Ok(());
    }

    let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
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
    // Remove query string
    let path_clean = path.split('?').next().unwrap_or(path);
    let parts: Vec<&str> = path_clean.trim_start_matches('/').split('/').collect();
    // Casos:
    // /ssh/SESSION_ID        -> parts=["ssh", "SESSION_ID"]          -> SESSION_ID
    // /ssh/SESSION_ID/0      -> parts=["ssh", "SESSION_ID", "0"]     -> SESSION_ID
    // /SESSION_ID            -> parts=["SESSION_ID"]                 -> SESSION_ID
    // /SESSION_ID/0          -> parts=["SESSION_ID", "0"]            -> SESSION_ID
    // Heuristica: se parts[0] e um prefixo de rota curto (<=10 chars, nao hex longo), usar parts[1]
    if parts.len() >= 2 && !parts[0].is_empty() {
        let first = parts[0];
        // Se o primeiro segmento parece ser um prefixo de rota (curto, como "ssh", "xhttp", "proxy")
        // e nao parece ser um session ID (que geralmente e hex longo ou UUID)
        let is_route_prefix = first.len() <= 10 && first.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        let second = parts[1];
        // O segundo segmento pode ser o session ID ou um numero de sequencia
        // Se o segundo segmento e apenas digitos, e um numero de sequencia -> usar first
        let second_is_seq = second.chars().all(|c| c.is_ascii_digit());
        if is_route_prefix && !second_is_seq {
            // Ex: /ssh/SESSION_ID ou /ssh/SESSION_ID/0 -> retorna SESSION_ID
            second.to_string()
        } else if !is_route_prefix {
            // Ex: /SESSION_ID/0 -> first e o session ID
            first.to_string()
        } else {
            // Fallback: retorna second
            second.to_string()
        }
    } else if parts.len() == 1 && !parts[0].is_empty() {
        parts[0].to_string()
    } else {
        String::new()
    }
}

fn extract_session_id_h2(path: &str) -> String {
    // Remove query string para analise do path
    let path_no_query = path.split('?').next().unwrap_or(path);

    // Tenta extrair do path /ssh/ID ou /ssh/ID/SEQ
    if let Some(pos) = path_no_query.find("/ssh/") {
        let after = &path_no_query[pos + 5..];
        // Pegar apenas o primeiro segmento (session ID), ignorar sequence number
        let sid = after.split('/').next().unwrap_or("");
        if !sid.is_empty() { return sid.to_string(); }
    }
    // Tenta extrair de query param ?session=ID ou ?id=ID
    if let Some(pos) = path.find("session=") {
        let sid = path[pos + 8..].split('&').next().unwrap_or("");
        if !sid.is_empty() { return sid.to_string(); }
    }
    if let Some(pos) = path.find("id=") {
        let sid = path[pos + 3..].split('&').next().unwrap_or("");
        if !sid.is_empty() { return sid.to_string(); }
    }
    extract_session_id(path)
}

fn generate_session_id() -> String {
    use std::time::SystemTime;
    let t = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    format!("{:x}{:x}", t.as_secs(), t.subsec_nanos())
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

fn build_tls_config(cert_path: &str, key_path: &str) -> Result<rustls::ServerConfig, XhttpError> {
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
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Certs ou keys vazios")));
    }

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.into_iter().next().unwrap())
        .map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)) as XhttpError)?;

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
    let mut status = String::from("@BDRProxy");
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
