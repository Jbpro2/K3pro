use std::env;
use std::io::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let port = get_port();
    let listener = TcpListener::bind(format!("[::]:{}", port)).await?;
    println!("[SDProxy] Iniciando na porta: {}", port);
    
    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client_stream).await {
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

async fn handle_client(mut client_stream: TcpStream) -> Result<(), Error> {
    let status = get_status();

    // 1. PEEK para ver se é HTTP ou SSH direto
    let mut peek_buf = [0u8; 1024];
    let n_peek = match timeout(Duration::from_secs(2), client_stream.peek(&mut peek_buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };

    let peek_str = String::from_utf8_lossy(&peek_buf[..n_peek]);
    
    // Se for HTTP (contém GET, POST, CONNECT ou HTTP/), faz o handshake
    if peek_str.contains("GET") || peek_str.contains("POST") || peek_str.contains("CONNECT") || peek_str.contains("HTTP/") {
        // Enviar 101
        client_stream.write_all(format!("HTTP/1.1 101 {}\r\n\r\n", status).as_bytes()).await?;
        client_stream.flush().await?;

        // Ler payload
        let mut buffer = vec![0; 4096];
        let n = client_stream.read(&mut buffer).await?;

        // Enviar 200
        client_stream.write_all(format!("HTTP/1.1 200 {}\r\n\r\n", status).as_bytes()).await?;
        client_stream.flush().await?;
    }

    // 2. Conectar ao backend (Default SSH)
    let addr_proxy = "127.0.0.1:22";
    let server_stream = match TcpStream::connect(addr_proxy).await {
        Ok(s) => s,
        Err(_) => TcpStream::connect("127.0.0.1:1194").await?
    };

    // 3. Tunnel bidirecional
    let (client_read, client_write) = client_stream.into_split();
    let (server_read, server_write) = server_stream.into_split();

    let client_read = Arc::new(Mutex::new(client_read));
    let client_write = Arc::new(Mutex::new(client_write));
    let server_read = Arc::new(Mutex::new(server_read));
    let server_write = Arc::new(Mutex::new(server_write));

    let c_to_s = transfer_data(client_read, server_write);
    let s_to_c = transfer_data(server_read, client_write);

    let _ = tokio::try_join!(c_to_s, s_to_c);

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
        if bytes_read == 0 { break; }
        let mut write_guard = write_stream.lock().await;
        write_guard.write_all(&buffer[..bytes_read]).await?;
        write_guard.flush().await?;
    }
    Ok(())
}

fn get_port() -> u16 {
    let args: Vec<String> = env::args().collect();
    let mut port = 8080;
    for i in 1..args.len() {
        if args[i] == "--port" || args[i] == "-p" {
            if i + 1 < args.len() { port = args[i + 1].parse().unwrap_or(8080); }
        }
    }
    port
}

fn get_status() -> String {
    let args: Vec<String> = env::args().collect();
    let mut status = String::from("@SDProxy");
    for i in 1..args.len() {
        if args[i] == "--status" || args[i] == "-s" {
            if i + 1 < args.len() { status = args[i + 1].clone(); }
        }
    }
    status
}
