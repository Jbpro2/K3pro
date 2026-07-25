# LKProxy v2.0 - com suporte xHTTP (SplitHTTP)

Proxy multi-protocolo em Rust com suporte exclusivo para o protocolo xHTTP (SplitHTTP) na porta 443, compatível com o cliente **XHTTP-DEMO**.

## O que mudou na v2.0

| Recurso | v1.0 | v2.0 |
|---------|------|------|
| xHTTP/SplitHTTP exclusivo | Não | Sim (opção 04) |
| TLS termination | Passthrough | Terminação com rustls |
| Porta 443 automática | Manual | Automática (opção 04) |
| Certificados auto-assinados | Não | Gerados automaticamente |
| UDP + QUIC na 443 | Manual | Auto-ativados |
| SocksRevive compatibilidade | Não | Sim |

## Instalação

```bash
# Clonar ou copiar os arquivos para o servidor
git clone https://github.com/MTSPRO2/CTProxy.git
cd CTProxy

# Substituir os arquivos pelo v2.0
cp menu.sh menu_original.sh.backup
# Copiar os novos arquivos para o repositório

# Compilar e instalar
chmod +x install.sh
./install.sh
```

## Uso

```bash
lkproxy    # Menu interativo
```

### Menu v2.0

```
╔══════════════════════════════════╗
║       LKProxy Menu Free v2.0     ║
╠══════════════════════════════════╣
║                                  ║
║ [01] - ABRIR PORTA               ║
║ [02] - FECHAR PORTA              ║
║ [03] - REINICIAR PORTA           ║
║ [04] - xHTTP SPLITHTTP (443)    ║
║                                  ║
║ [00] - SAIR                      ║
╚══════════════════════════════════╝
```

### Opção 04 - xHTTP SplitHTTP (Porta 443)

Esta opção é **exclusiva** para o protocolo xHTTP (SplitHTTP) e funciona assim:

1. **Porta fixa 443** - Não pode ser alterada
2. **TLS obrigatório** - Certificado auto-assinado gerado automaticamente
3. **SSH only** - Tunnel para SSH local (127.0.0.1:22)
4. **UDP + QUIC** - Ativados automaticamente
5. **Status HTTP** - Cabeçalho retornado ao cliente (padrão: @LKProxy)

### Fluxo do xHTTP

```
Cliente (SocksRevive)          Servidor (LKProxy)
       │                              │
       ├── TCP connect :443 ──────────┤
       ├── TLS ClientHello ───────────┤
       │                              ├── TLS handshake (rustls)
       │                              ├── TLS ServerHello
       │                              ├── TLS decodificado
       │                              │
       ├── HTTP/2 GET /ssh/{id} ─────┤
       │                              ├── Sessão criada
       │                              ├── Conecta SSH backend
       │                              ├── Streaming chunked
       │                              │
       │◄── HTTP 200 + chunks ────────┤ (dados SSH do servidor)
       │                              │
       ├── HTTP/2 POST /ssh/{id}/0 ──┤ (dados SSH do cliente)
       │                              ├── Encaminha para SSH backend
       │                              │
       ├── HTTP/2 POST /ssh/{id}/1 ──┤
       │                              ├── Encaminha para SSH backend
```

### Configuração no SocksRevive-XHTTP-DEMO

| Campo | Valor |
|-------|-------|
| Server | IP do servidor LKProxy |
| Port | 443 |
| SNI | Qualquer domínio (trust-all) |
| XHTTP Host | IP do servidor ou vazio |
| XHTTP Path | /ssh |
| XHTTP TLS | HABILITADO |
| Username | Usuário SSH |
| Password | Senha SSH |

## Flags do Binário

```
-p PORTA       Porta TCP (padrão: 80)
-s STATUS      Status HTTP (padrão: @LKProxy)
-t             Habilitar TLS
-ssh           SSH only (tunnel para 127.0.0.1:22)
-u             Habilitar UDP
-q             Habilitar QUIC
-x             xHTTP mode (força porta 443, TLS, SSH only)
```

## Notas sobre TLS

O TLS na v2.0 usa **terminação local** com `rustls`:

1. O certificado e chave são gerados em `/opt/lkproxy/`
2. O proxy faz handshake TLS completo com o cliente
3. Os dados decodificados são roteados para o handler correto
4. Para xHTTP: os dados HTTP/2 ficam visíveis após TLS

## Troubleshooting

```bash
# Ver logs
journalctl -u proxy-443.service -f

# Verificar SSH
systemctl status ssh

# Testar TLS
openssl s_client -connect 127.0.0.1:443

# Verificar porta
ss -tlnp | grep 443
```

## Requisitos

- Rust 1.70+
- systemd
- OpenSSH Server (rodando na porta 22)
- OpenSSL (para certificados)
- Porta 443 aberta no firewall
