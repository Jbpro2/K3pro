use std::env;
use std::io::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

mod socks5;
mod websocket;
mod security;
mod tcp_fallback;
mod tls;
mod ssh;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let port = get_port();
    let listener = TcpListener::bind(format!("[::]:{}", port)).await?;
    println!("Iniciando servico na porta: {}", port);
    start_http(listener).await;
    Ok(())
}

async fn start_http(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client_stream).await {
                        println!("Erro ao processar cliente {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                println!("Erro ao aceitar conexao: {}", e);
            }
        }
    }
}

async fn handle_client(client_stream: TcpStream) -> Result<(), Error> {
    // PEEK primeiro byte para detectar TLS ClientHello (0x16)
    let mut peek_buf = [0u8; 1];
    let peek_result = timeout(Duration::from_secs(5), client_stream.peek(&mut peek_buf)).await;

    if let Ok(Ok(1)) = peek_result {
        if peek_buf[0] == 0x16 {
            // TLS ClientHello — fazer passthrough direto para SSH (0.0.0.0:22)
            // O SSH/SSH tunnel recebe o TLS handshake diretamente
            return handle_tls_passthrough(client_stream).await;
        }
    }

    // Conexão não-TLS — lógica do AWProxy (101 → read → 200 → peek → tunnel)
    handle_bsproxy(client_stream).await
}

/// TLS Passthrough — encaminha o handshake TLS diretamente para o SSH backend
/// Usado pelo HTTP Injector no modo SSL/TLS Proxy → SSH
async fn handle_tls_passthrough(client_stream: TcpStream) -> Result<(), Error> {
    // Tentar SSH primeiro, fallback para VPN
    let server_connect = TcpStream::connect("0.0.0.0:22").await;
    let server_stream = match server_connect {
        Ok(s) => s,
        Err(e) => {
            println!("TLS Passthrough: SSH nao disponivel em 0.0.0.0:22, tentando 0.0.0.0:1194");
            match TcpStream::connect("0.0.0.0:1194").await {
                Ok(s) => s,
                Err(e2) => {
                    println!("TLS Passthrough: Ambos falharam: {}, {}", e, e2);
                    return Ok(());
                }
            }
        }
    };

    let (client_read, client_write) = client_stream.into_split();
    let (server_read, server_write) = server_stream.into_split();

    let client_read = Arc::new(Mutex::new(client_read));
    let client_write = Arc::new(Mutex::new(client_write));
    let server_read = Arc::new(Mutex::new(server_read));
    let server_write = Arc::new(Mutex::new(server_write));

    let c2s = transfer_data(client_read, server_write);
    let s2c = transfer_data(server_read, client_write);

    tokio::try_join!(c2s, s2c)?;
    Ok(())
}

/// BSProxy padrão — lógica do AWProxy (101 → read → 200 → peek → tunnel)
async fn handle_bsproxy(mut client_stream: TcpStream) -> Result<(), Error> {
    let status = get_status();

    // SEMPRE envia 101 primeiro
    client_stream
        .write_all(format!("HTTP/1.1 101 {}\r\n\r\n", status).as_bytes())
        .await?;

    // SEMPRE le do cliente
    let mut buffer = vec![0; 1024];
    client_stream.read(&mut buffer).await?;

    // SEMPRE envia 200
    client_stream
        .write_all(format!("HTTP/1.1 200 {}\r\n\r\n", status).as_bytes())
        .await?;

    // Detecta SSH vs VPN pelo peek
    let addr_proxy = if let Ok(data) = timeout(Duration::from_secs(1), peek_stream(&mut client_stream)).await
        .unwrap_or_else(|_| Ok(String::new()))
    {
        if data.contains("SSH") || data.is_empty() {
            "0.0.0.0:22"
        } else {
            "0.0.0.0:1194"
        }
    } else {
        "0.0.0.0:22"
    };

    let server_connect = TcpStream::connect(addr_proxy).await;
    if server_connect.is_err() {
        println!("erro ao iniciar conexao para o proxy ");
        return Ok(());
    }

    let server_stream = server_connect?;

    let (client_read, client_write) = client_stream.into_split();
    let (server_read, server_write) = server_stream.into_split();

    let client_read = Arc::new(Mutex::new(client_read));
    let client_write = Arc::new(Mutex::new(client_write));
    let server_read = Arc::new(Mutex::new(server_read));
    let server_write = Arc::new(Mutex::new(server_write));

    let client_to_server = transfer_data(client_read, server_write);
    let server_to_client = transfer_data(server_read, client_write);

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}

async fn transfer_data(
    read_stream: Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>,
    write_stream: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
) -> Result<(), Error> {
    let mut buffer = [0; 8192];
    loop {
        let bytes_read = {
            let mut read_guard = read_stream.lock().await;
            read_guard.read(&mut buffer).await?
        };

        if bytes_read == 0 {
            break;
        }

        let mut write_guard = write_stream.lock().await;
        write_guard.write_all(&buffer[..bytes_read]).await?;
    }

    Ok(())
}

async fn peek_stream(stream: &TcpStream) -> Result<String, Error> {
    let mut peek_buffer = vec![0; 8192];
    let bytes_peeked = stream.peek(&mut peek_buffer).await?;
    let data = &peek_buffer[..bytes_peeked];
    let data_str = String::from_utf8_lossy(data);
    Ok(data_str.to_string())
}

fn get_port() -> u16 {
    let args: Vec<String> = env::args().collect();
    let mut port = 80;

    for i in 1..args.len() {
        if args[i] == "--port" || args[i] == "-p" {
            if i + 1 < args.len() {
                port = args[i + 1].parse().unwrap_or(80);
            }
        }
    }

    port
}

fn get_status() -> String {
    let args: Vec<String> = env::args().collect();
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
