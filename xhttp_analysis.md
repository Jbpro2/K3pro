# Análise do Protocolo xHTTP - XHTTP DEMO

## Protocolo Real (SplitHTTP)

O cliente SocksRevive usa **SplitHTTP** (também conhecido como XHTTP) que opera sobre **HTTP/2** com dois canais separados:

### Downlink (GET) - Servidor → Cliente
- `GET {path}/{session-id}` 
- Response HTTP/2 com **body streaming** (long-lived)
- O servidor mantém a conexão aberta e envia dados do SSH continuamente
- Path exemplo: `/ssh/abc123def456`

### Uplink (POST) - Cliente → Servidor
- `POST {path}/{session-id}/{sequence-number}`
- Cada pacote SSH é enviado como um POST separado, **sequenciado** (0, 1, 2, ...)
- Server responde `200` após processar cada pacote
- **Single-flight**: um POST de cada vez, espera o 200 antes do próximo
- Path exemplo: `/ssh/abc123def456/0`, `/ssh/abc123def456/1`, ...

### Headers
- `Host`: SNI ou host CDN configurado
- `User-Agent`: Chrome 124
- `Accept`: `*/*`
- Content-Type do POST: `application/octet-stream`

### Configuração do Cliente
- **Endpoint/Server**: IP do servidor proxy
- **Port**: porta (ex: 443)
- **SNI**: host para TLS SNI (opcional, domain fronting)
- **Host**: header Host para CDN (opcional)
- **Path**: default `/ssh` (ou `/xhttp`)
- **TLS**: booleano (default: habilitado)

### Fluxo Completo
1. Cliente faz `GET https://sni:port/path/session-id` → servidor abre stream
2. Cliente faz `POST https://sni:port/path/session-id/0` com bytes SSH → servidor responde 200
3. Cliente faz `POST https://sni:port/path/session-id/1` → servidor responde 200
4. ... (continua sequenciado)
5. Dados do servidor (SSH do backend) vêm pelo GET stream aberto
6. Dados do cliente (SSH do app) vão pelos POSTs sequenciados

### Requisitos do Servidor
1. Aceitar HTTP/2 (TLS ou direto)
2. Servir GET como **response body streaming** (SSE-like, mantém conexão aberta)
3. Aceitar POSTs sequenciados e encaminhar para backend SSH/VPN
4. Bidirecional: dados do backend → GET response; dados do cliente → POST body

### O que o LKProxy atual NÃO faz
- Não serve GET como streaming (fecha rápido demais)
- Não aceita POSTs com sequence numbers
- Não faz proxy HTTP/2
- Não faz o bridge bidirecional correto
