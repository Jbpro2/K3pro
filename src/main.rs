use std::env;
use std::io::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let port = get_port();
    let status = get_status();
    let use_udp = has_arg("-u");
    let use_quic = has_arg("-q");
    let quic_port = get_quic_port();

    println!("[BDRProxy] Multi-protocolo v2.5.0");
    println!("[TCP] Porta: {}", port);
    
    if use_udp {
        println!("[UDP] Habilitado na porta: {}", port);
        let status_udp = status.clone();
        tokio::spawn(async move {
            if let Err(e) = start_udp(port, &status_udp).await {
                println!("[UDP] Erro: {}", e);
            }
        });
    }

    if use_quic {
        println!("[QUIC] Habilitado na porta: {}", quic_port);
        // Implementação simplificada de QUIC placeholder
        // Para QUIC real, integrar com crate quinn
    }

    let listener = TcpListener::bind(format!("[::]:{}", port)).await?;
    println!("Aguardando conexoes TCP...");
    
    start_http(listener, status).await;
    Ok(())
}

async fn start_http(listener: TcpListener, status: String) {
    let status_arc = Arc::new(status);
    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                let status = status_arc.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(client_stream, &status).await {
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

async fn handle_client(mut client_stream: TcpStream, status: &str) -> Result<(), Error> {
    // SEMPRE envia 101 primeiro
    client_stream
        .write_all(format!("HTTP/1.1 101 {}\r\n\r\n", status).as_bytes())
        .await?;

    // SEMPRE le do cliente
    let mut buffer = vec![0; 1024];
    let _ = client_stream.read(&mut buffer).await?;

    // SEMPRE envia 200
    client_stream
        .write_all(format!("HTTP/1.1 200 {}\r\n\r\n", status).as_bytes())
        .await?;

    // Detecta SSH vs VPN pelo peek
    let mut addr_proxy = "127.0.0.1:22";
    let result = timeout(Duration::from_secs(1), peek_stream(&mut client_stream)).await
        .unwrap_or_else(|_| Ok(String::new()));

    if let Ok(data) = result {
        if data.contains("SSH") || data.is_empty() {
            addr_proxy = "127.0.0.1:22";
        } else {
            addr_proxy = "127.0.0.1:1194";
        }
    }

    let server_connect = TcpStream::connect(addr_proxy).await;
    if server_connect.is_err() {
        return Ok(());
    }

    let server_stream = server_connect?;
    let (mut client_read, mut client_write) = client_stream.into_split();
    let (mut server_read, mut server_write) = server_stream.into_split();

    let _ = tokio::join!(
        tokio::io::copy(&mut client_read, &mut server_write),
        tokio::io::copy(&mut server_read, &mut client_write)
    );

    Ok(())
}

async fn start_udp(port: u16, _status: &str) -> Result<(), Error> {
    let socket = UdpSocket::bind(format!("[::]:{}", port)).await?;
    let mut buf = [0u8; 2048];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        // Proxy UDP simplificado (encaminha para 127.0.0.1:22 ou 1194 se necessário)
        // Aqui apenas logamos por enquanto para manter estabilidade
        println!("[UDP] {} bytes de {}", len, addr);
    }
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
    for i in 1..args.len() {
        if (args[i] == "--port" || args[i] == "-p") && i + 1 < args.len() {
            return args[i + 1].parse().unwrap_or(8080);
        }
    }
    8080
}

fn get_quic_port() -> u16 {
    let args: Vec<String> = env::args().collect();
    for i in 1..args.len() {
        if args[i] == "--quic-port" && i + 1 < args.len() {
            return args[i + 1].parse().unwrap_or(8001);
        }
    }
    8001
}

fn get_status() -> String {
    let args: Vec<String> = env::args().collect();
    for i in 1..args.len() {
        if (args[i] == "--status" || args[i] == "-s") && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    "@SDProxy".to_string()
}

fn has_arg(arg: &str) -> bool {
    env::args().any(|a| a == arg)
}
