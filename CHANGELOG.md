# LKProxy - Changelog

## v2.4.1 - xHTTP SplitHTTP (DTUNNEL Fix)

### Novo
- **Correção SplitHTTP** — suporte completo ao protocolo SplitHTTP usado no DTUNNEL
- **Persistência HTTP/1.1** — headers `Connection: keep-alive` obrigatórios para manter o canal GET aberto
- **ALPN http/1.1** — forçando ALPN http/1.1 no TLS para evitar falhas de handshake no DTUNNEL
- **Path Parsing** — suporte a paths com sequence numbers (ex: `/ssh/session/0`)
- **Headers de Streaming** — inclusão de headers `Cache-Control`, `Pragma` e `Expires` para evitar cache de proxy intermediário (CDN)


## v0.3.0 - Multi-Protocolo (TCP + UDP + QUIC)

### Novo

- **Suporte UDP** — listener UDP na mesma porta TCP, encaminhamento de datagramas
- **Suporte QUIC** — servidor QUIC completo com `quinn` crate, streams bidirecionais
- **Certificado auto-assinado** — geração automática de cert.pem e key.pem via `rcgen`
- **Ativação automática** — ao usar `-p 443 -t`, UDP e QUIC são ativados automaticamente
- **Flags novas:**
  - `-u` / `--udp` — ativar UDP na porta TCP
  - `-q` / `--quic` — ativar QUIC (porta separada via `--quic-port` ou mesma)

### Flags de Uso

```bash
# Multi-protocolo completo (TCP + UDP + QUIC) na 443
./lkproxy -p 443 -t -ssh

# Apenas TCP + UDP
./lkproxy -p 443 -t -u -ssh

# Apenas TCP + QUIC
./lkproxy -p 443 -t -q -ssh

# QUIC em porta separada
./lkproxy -p 443 -t -q --quic-port 8001 -ssh
```

### Configuração do menu.sh

Ao abrir a porta 443 com HTTPS habilitado, o proxy agora inicia automaticamente:
- TCP:443 (xHTTP, Proto, WebSocket, TLS, SSH)
- UDP:443 (proxy UDP para xHTTP/Proto)
- QUIC:8001 (proxy QUIC com certificado auto-assinado)

### Certificados

Os certificados QUIC são gerados automaticamente em `/opt/lkproxy/cert.pem` e `/opt/lkproxy/key.pem` na primeira execução com QUIC ativo.

### Arquitetura

```
Cliente → [TCP:443] → LKProxy → SSH:22 / VPN:1194
Cliente → [UDP:443] → LKProxy → SSH:22 / VPN:1194
Cliente → [QUIC:8001] → LKProxy → SSH:22 / VPN:1194
```

---

## v0.2.0 - xHTTP/Proto + TLS

### Novo
- Handler xHTTP com handshake HTTP/101 + 200 e headers customizados
- Handler Proto para conexões TCP raw/binary
- TLS com passthrough e terminação (flags -t e -ssh)
- Detecção aprimorada de protocolos (TLS, xHTTP, Proto, SOCKS5)
- Integração de todos os handlers existentes
- WebSocket com suporte a Sec-WebSocket-Accept (SHA-1 + Base64)
- Fallback automático SSH↔VPN em todos os handlers
