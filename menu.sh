#!/bin/bash

# ============================================
# SDProxy Menu - Free v2.3
# ============================================

SDPROXY="/opt/sdproxy/proxy"
SDPROXY_XHTTP="/opt/sdproxy/proxy-xhttp"
SYSTEMD_DIR="/etc/systemd/system"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================
# Banner SDPROXY
# ============================================
show_banner() {
    echo -e "${BLUE}${BOLD} ███████╗██████╗ ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗"
    echo -e "${NC} ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝"
    echo -e "${BLUE}${BOLD} ███████╗██║  ██║██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ "
    echo -e "${NC} ╚════██║██║  ██║██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  "
    echo -e "${BLUE}${BOLD} ███████║██████╔╝██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   "
    echo -e "${NC} ╚══════╝╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   "
    echo -e "${BLUE}${BOLD}--------------------------------------------------------------${NC}"
}

# ============================================
# Mostrar portas ativas (organizado)
# ============================================
show_active_ports() {
    ACTIVE=""
    XHTTP_ACTIVE=false

    # Verificar portas padrão (proxy-*)
    for service_file in ${SYSTEMD_DIR}/proxy-*.service; do
        if [ -f "$service_file" ]; then
            PORT=$(basename "$service_file" .service | sed 's/proxy-//')
            if systemctl is-active --quiet "proxy-${PORT}.service" 2>/dev/null; then
                if [ "$PORT" = "443" ]; then
                    XHTTP_ACTIVE=true
                else
                    ACTIVE="$ACTIVE $PORT"
                fi
            fi
        fi
    done

    # Montar linha de portas
    echo -ne "${CYAN}║ ${YELLOW}Porta(s) ativa(s):${NC}"
    echo -ne "${WHITE}"
    if [ -n "$ACTIVE" ]; then
        echo -ne "${YELLOW}${ACTIVE}${NC}"
    fi
    if [ "$XHTTP_ACTIVE" = true ]; then
        if [ -n "$ACTIVE" ]; then
            echo -ne " ${WHITE}443"
        else
            echo -ne "${YELLOW}443${NC}"
        fi
    fi
    if [ -z "$ACTIVE" ] && [ "$XHTTP_ACTIVE" = false ]; then
        echo -ne "${RED}nenhuma${NC}"
    fi
    echo -ne "${CYAN}                             ║${NC}"
    echo ""
}

# ============================================
# Menu Principal
# ============================================
show_menu() {
    clear
    show_banner
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        SDProxy Menu Free v2.3            ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
    show_active_ports
    echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${WHITE}[01]${NC} - ABRIR PORTA                    ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${WHITE}[02]${NC} - FECHAR PORTA                   ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${WHITE}[03]${NC} - REINICIAR PORTA                ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${MAGENTA}[04]${NC} - xHTTP_SSH / SSL TUNNEL ${GREEN}(${YELLOW}443${GREEN})${NC}  ${CYAN}║${NC}"
    echo -e "${CYAN}║                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${WHITE}[00]${NC} - SAIR                           ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -n "Escolha uma opção: "
}

# ============================================
# Abrir Porta (padrão - 80, 8080, etc)
# ============================================
open_port() {
    clear
    show_banner
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           Abrir Porta                    ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${WHITE}Portas padrão: 80, 8080, 8880, 3128${NC}     ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${YELLOW}Porta 443: use opção [04] xHTTP/SSL${NC}    ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""

    read -p "Porta: " PORT
    if [[ -z "$PORT" ]]; then
        echo -e "${RED}Porta inválida!${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    if [[ "$PORT" == "443" ]]; then
        echo -e "${YELLOW}Para porta 443, use a opção [04] xHTTP_SSH / SSL TUNNEL.${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    if [[ ! "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        echo -e "${RED}Porta inválida!${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    if systemctl is-active --quiet "proxy-${PORT}.service" 2>/dev/null; then
        echo -e "${RED}Porta ${PORT} já está em uso!${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    read -p "Habilitar o HTTPS? (s/n): " HTTPS
    HTTPS=$(echo "$HTTPS" | tr '[:upper:]' '[:lower:]')
    echo ""

    read -p "Status HTTP (Padrão: @SDProxy): " STATUS
    if [[ -z "$STATUS" ]]; then
        STATUS="@SDProxy"
    fi

    read -p "Habilitar somente SSH? (s/n): " SSH_ONLY
    SSH_ONLY=$(echo "$SSH_ONLY" | tr '[:upper:]' '[:lower:]')
    echo ""

    mkdir -p /opt/sdproxy

    if [ ! -f "$SDPROXY" ]; then
        echo -e "${RED}SDProxy não encontrado! Execute o install.sh primeiro.${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    create_service "$PORT" "$HTTPS" "$STATUS" "$SSH_ONLY"

    echo -e "${GREEN}Iniciando proxy na porta ${PORT}...${NC}"
    systemctl daemon-reload
    systemctl enable "proxy-${PORT}.service" 2>/dev/null
    systemctl start "proxy-${PORT}.service" 2>/dev/null

    sleep 2

    if systemctl is-active --quiet "proxy-${PORT}.service" 2>/dev/null; then
        echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  Proxy iniciado na porta ${PORT}            ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    else
        echo -e "${RED}Falha ao iniciar o proxy na porta ${PORT}!${NC}"
        echo -e "${YELLOW}Verifique: journalctl -u proxy-${PORT}.service${NC}"
    fi

    echo ""
    read -p "Enter pra continuar..."
}

# ============================================
# xHTTP SplitHTTP + SSL TUNNEL - Porta 443
# ============================================
open_xhttp() {
    clear
    show_banner
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  xHTTP_SSH / SSL TUNNEL - Porta 443      ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${WHITE}Protocolos suportados:                   ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}• xHTTP SplitHTTP${NC} (SocksRevive)       ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}• SSL TUNNEL${NC} (HTTP Injector)         ${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}• HTTP direto${NC} (qualquer client)     ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""

    if systemctl is-active --quiet "proxy-443.service" 2>/dev/null; then
        echo -e "${RED}Porta 443 já está em uso!${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    mkdir -p /opt/sdproxy

    if [ ! -f "$SDPROXY_XHTTP" ]; then
        echo -e "${RED}sdproxy-xhttp não encontrado! Execute o install.sh primeiro.${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    read -p "Status HTTP (Padrão: @SDProxy): " STATUS
    if [[ -z "$STATUS" ]]; then
        STATUS="@SDProxy"
    fi

    read -p "Porta SSH backend (Padrão: 22): " SSH_PORT
    if [[ -z "$SSH_PORT" ]]; then
        SSH_PORT="22"
    fi

    # Gerar certificados se não existirem
    echo -e "${GREEN}Verificando certificados TLS...${NC}"
    if [ ! -f "/opt/sdproxy/cert.pem" ] || [ ! -f "/opt/sdproxy/key.pem" ]; then
        echo -e "${YELLOW}Gerando certificado auto-assinado...${NC}"
        openssl req -x509 -newkey rsa:2048 -keyout /opt/sdproxy/key.pem \
            -out /opt/sdproxy/cert.pem -days 365 -nodes \
            -subj "/CN=sdproxy/O=SDProxy/C=BR" 2>/dev/null
        echo -e "${GREEN}Certificados gerados.${NC}"
    else
        echo -e "${GREEN}Certificados TLS existentes.${NC}"
    fi

    echo ""
    echo -e "${GREEN}Configuração:${NC}"
    echo -e "  Porta: ${YELLOW}443${NC}"
    echo -e "  TLS: ${GREEN}OBRIGATÓRIO (auto-assinado)${NC}"
    echo -e "  SSH Backend: ${YELLOW}${SSH_PORT}${NC}"
    echo -e "  Status: ${YELLOW}${STATUS}${NC}"
    echo -e "  Protocolos: ${GREEN}xHTTP + SSL Tunnel + HTTP${NC}"
    echo ""

    create_xhttp_service "443" "$STATUS" "$SSH_PORT"

    echo -e "${GREEN}Iniciando xHTTP_SSH / SSL TUNNEL na porta 443...${NC}"
    systemctl daemon-reload
    systemctl enable "proxy-443.service" 2>/dev/null
    systemctl start "proxy-443.service" 2>/dev/null

    sleep 3

    if systemctl is-active --quiet "proxy-443.service" 2>/dev/null; then
        echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  ATIVO NA PORTA 443                     ║${NC}"
        echo -e "${GREEN}║  xHTTP_SSH + SSL TUNNEL                 ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}┌────────────────────────────────────────────┐${NC}"
        echo -e "${YELLOW}│  SocksRevive (xHTTP SplitHTTP):          │${NC}"
        echo -e "${YELLOW}│    Server: IP deste servidor             │${NC}"
        echo -e "${YELLOW}│    Port: 443                             │${NC}"
        echo -e "${YELLOW}│    SNI: qualquer domínio (trust-all)     │${NC}"
        echo -e "${YELLOW}│    XHTTP Path: /ssh                      │${NC}"
        echo -e "${YELLOW}│    XHTTP TLS: HABILITADO                 │${NC}"
        echo -e "${YELLOW}├────────────────────────────────────────────┤${NC}"
        echo -e "${YELLOW}│  HTTP Injector (SSL Tunnel):             │${NC}"
        echo -e "${YELLOW}│    Server: IP deste servidor             │${NC}"
        echo -e "${YELLOW}│    Port: 443                             │${NC}"
        echo -e "${YELLOW}│    SSL Proxy: HABILITADO                 │${NC}"
        echo -e "${YELLOW}│    Payload: default                      │${NC}"
        echo -e "${YELLOW}└────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "${YELLOW}Logs: journalctl -u proxy-443.service -f${NC}"
    else
        echo -e "${RED}Falha ao iniciar na porta 443!${NC}"
        echo -e "${YELLOW}Logs: journalctl -u proxy-443.service -f${NC}"
    fi

    echo ""
    read -p "Enter pra continuar..."
}

# ============================================
# Criar serviço padrão
# ============================================
create_service() {
    local PORT=$1
    local HTTPS=$2
    local STATUS=$3
    local SSH_ONLY=$4
    local SERVICE_FILE="${SYSTEMD_DIR}/proxy-${PORT}.service"

    EXTRA_ARGS="-p ${PORT}"

    if [[ -n "$STATUS" ]]; then
        EXTRA_ARGS="${EXTRA_ARGS} -s ${STATUS}"
    fi

    if [[ "$HTTPS" == "s" ]]; then
        EXTRA_ARGS="${EXTRA_ARGS} -t"
    fi

    if [[ "$SSH_ONLY" == "s" ]]; then
        EXTRA_ARGS="${EXTRA_ARGS} -ssh"
    fi

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SDProxy - Porta ${PORT}
After=network.target

[Service]
Type=simple
ExecStart=${SDPROXY} ${EXTRA_ARGS}
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=/opt/sdproxy

[Install]
WantedBy=multi-user.target
EOF
}

# ============================================
# Criar serviço xHTTP + SSL Tunnel (porta 443)
# ============================================
create_xhttp_service() {
    local PORT=$1
    local STATUS=$2
    local SSH_PORT=$3
    local SERVICE_FILE="${SYSTEMD_DIR}/proxy-${PORT}.service"

    EXTRA_ARGS="-p ${PORT} -s ${STATUS} --ssh-port ${SSH_PORT}"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SDProxy xHTTP + SSL Tunnel - Porta ${PORT}
After=network.target

[Service]
Type=simple
ExecStart=${SDPROXY_XHTTP} ${EXTRA_ARGS}
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=/opt/sdproxy

[Install]
WantedBy=multi-user.target
EOF
}

# ============================================
# Fechar Porta
# ============================================
close_port() {
    clear
    show_banner
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           Fechar Porta                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""

    show_active_ports

    read -p "Porta: " PORT
    if [[ -z "$PORT" ]]; then
        echo -e "${RED}Porta inválida!${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    if systemctl is-active --quiet "proxy-${PORT}.service" 2>/dev/null; then
        systemctl stop "proxy-${PORT}.service"
        systemctl disable "proxy-${PORT}.service" 2>/dev/null
        rm -f "${SYSTEMD_DIR}/proxy-${PORT}.service"
        systemctl daemon-reload
        echo -e "${GREEN}Porta ${PORT} fechada com sucesso!${NC}"
    else
        echo -e "${RED}Porta ${PORT} não está ativa!${NC}"
    fi

    echo ""
    read -p "Enter pra continuar..."
}

# ============================================
# Reiniciar Porta
# ============================================
restart_port() {
    clear
    show_banner
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          Reiniciar Porta                 ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""

    show_active_ports

    read -p "Porta: " PORT
    if [[ -z "$PORT" ]]; then
        echo -e "${RED}Porta inválida!${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    if systemctl is-active --quiet "proxy-${PORT}.service" 2>/dev/null; then
        echo -e "${YELLOW}Reiniciando proxy na porta ${PORT}...${NC}"
        systemctl restart "proxy-${PORT}.service"
        sleep 2

        if systemctl is-active --quiet "proxy-${PORT}.service" 2>/dev/null; then
            echo -e "${GREEN}Proxy reiniciado na porta ${PORT}!${NC}"
        else
            echo -e "${RED}Falha ao reiniciar proxy na porta ${PORT}!${NC}"
        fi
    else
        echo -e "${RED}Porta ${PORT} não está ativa!${NC}"
    fi

    echo ""
    read -p "Enter pra continuar..."
}

# ============================================
# Loop Principal
# ============================================

while true; do
    show_menu
    read OPTION
    case $OPTION in
        01|1) open_port ;;
        02|2) close_port ;;
        03|3) restart_port ;;
        04|4) open_xhttp ;;
        00|0) echo -e "${GREEN}Saindo...${NC}"; exit 0 ;;
        *) echo -e "${RED}Opção inválida!${NC}"; sleep 1 ;;
    esac
done
