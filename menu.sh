#!/bin/bash

# ============================================
# LKProxy Menu - Free v2.3
# ============================================

SDPROXY="/opt/lkproxy/proxy"
SDPROXY_XHTTP="/opt/lkproxy/proxy-xhttp"
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

BOX_WIDTH=46   

strip_len() {
    local clean
    clean=$(echo -ne "$1" | sed -r 's/\x1B\[[0-9;]*[mK]//g')
    echo -n "${#clean}"
}

NBSP=$'\xc2\xa0'

box_line() {
    local content="$1"
    local visible_len
    visible_len=$(strip_len "$content")
    local pad=$(( BOX_WIDTH - visible_len ))
    [ $pad -lt 0 ] && pad=0
    echo -ne "${CYAN}║${NC} "
    echo -ne "${content}"
    local i
    for ((i=0; i<pad; i++)); do
        printf '%s' "$NBSP"
    done
    echo -e "${CYAN}║${NC}"
}

box_top() {
    printf "${CYAN}╔"
    printf '═%.0s' $(seq 1 $((BOX_WIDTH + 2)))
    printf "╗${NC}\n"
}

box_mid() {
    printf "${CYAN}╠"
    printf '═%.0s' $(seq 1 $((BOX_WIDTH + 2)))
    printf "╣${NC}\n"
}

box_bottom() {
    printf "${CYAN}╚"
    printf '═%.0s' $(seq 1 $((BOX_WIDTH + 2)))
    printf "╝${NC}\n"
}

# ============================================
# Banner SDPROXY
# ============================================
show_banner() {
echo -e "${PURPLE}${BOLD} ██╗     ██╗  ██╗██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗${NC}"
echo -e "${PURPLE}${BOLD} ██║     ██║ ██╔╝██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝${NC}"
echo -e "${BLUE}${BOLD} ██║     █████╔╝ ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ${NC}"
echo -e "${BLUE}${BOLD} ██║     ██╔═██╗ ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ${NC}"
echo -e "${PURPLE}${BOLD} ███████╗██║  ██╗██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ${NC}"
echo -e "${BLUE}${BOLD} ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ${NC}"
echo -e "${BLUE}${BOLD}--------------------------------------------------------------${NC}"
}

# ============================================
# Mostrar portas ativas (organizado)
# ============================================
show_active_ports() {
    ACTIVE=""
    XHTTP_ACTIVE=false

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

    local ports_str=""
    if [ -n "$ACTIVE" ]; then
        ports_str="${YELLOW}${ACTIVE# }${NC}"
    fi
    if [ "$XHTTP_ACTIVE" = true ]; then
        if [ -n "$ports_str" ]; then
            ports_str="${ports_str} ${YELLOW}443${NC}"
        else
            ports_str="${YELLOW}443${NC}"
        fi
    fi
    if [ -z "$ports_str" ]; then
        ports_str="${RED}nenhuma${NC}"
    fi

    box_line "${YELLOW}Porta(s) ativa(s):${NC} ${ports_str}"
}

# ============================================
# Menu Principal
# ============================================
show_menu() {
    clear
    show_banner
    echo ""
    box_top
    box_line "${WHITE}${BOLD}LKProxy Menu Free v2.3${NC}"
    box_mid
    show_active_ports
    box_mid
    box_line "${WHITE}[01]${NC} - ABRIR PORTA"
    box_line "${WHITE}[02]${NC} - FECHAR PORTA"
    box_line "${WHITE}[03]${NC} - REINICIAR PORTA"
    box_line "${MAGENTA}[04]${NC} - xHTTP_SSH / SSL TUNNEL ${GREEN}(${YELLOW}443${GREEN})${NC}"
    box_line ""
    box_line "${WHITE}[00]${NC} - SAIR"
    box_bottom
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
    box_top
    box_line "${WHITE}${BOLD}Abrir Porta${NC}"
    box_mid
    box_line "${WHITE}Portas padrão: 80, 8080, 8880, 3128${NC}"
    box_line "${YELLOW}Porta 443: use opção [04] xHTTP/SSL${NC}"
    box_bottom
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

    read -p "Status HTTP (Padrão: @LKProxy): " STATUS
    if [[ -z "$STATUS" ]]; then
        STATUS="@LKProxy"
    fi

    read -p "Habilitar somente SSH? (s/n): " SSH_ONLY
    SSH_ONLY=$(echo "$SSH_ONLY" | tr '[:upper:]' '[:lower:]')
    echo ""

    mkdir -p /opt/lkproxy

    if [ ! -f "$LKPROXY" ]; then
        echo -e "${RED}LKProxy não encontrado! Execute o install.sh primeiro.${NC}"
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
        box_top
        box_line "${GREEN}Proxy iniciado na porta ${PORT}${NC}"
        box_bottom
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
    box_top
    box_line "${WHITE}${BOLD}xHTTP_SSH / SSL TUNNEL - Porta 443${NC}"
    box_mid
    box_line "${WHITE}Protocolos suportados:${NC}"
    box_line "${GREEN}• xHTTP SplitHTTP${NC} (SocksRevive)"
    box_line "${GREEN}• SSL TUNNEL${NC} (HTTP Injector)"
    box_line "${GREEN}• HTTP direto${NC} (qualquer client)"
    box_bottom
    echo ""

    if systemctl is-active --quiet "proxy-443.service" 2>/dev/null; then
        echo -e "${RED}Porta 443 já está em uso!${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    mkdir -p /opt/lkproxy

    if [ ! -f "$LKPROXY_XHTTP" ]; then
        echo -e "${RED}lkproxy-xhttp não encontrado! Execute o install.sh primeiro.${NC}"
        read -p "Enter pra continuar..."
        return
    fi

    read -p "Status HTTP (Padrão: @LKProxy): " STATUS
    if [[ -z "$STATUS" ]]; then
        STATUS="@LKProxy"
    fi

    read -p "Porta SSH backend (Padrão: 22): " SSH_PORT
    if [[ -z "$SSH_PORT" ]]; then
        SSH_PORT="22"
    fi

    echo -e "${GREEN}Verificando certificados TLS...${NC}"
    if [ ! -f "/opt/lkproxy/cert.pem" ] || [ ! -f "/opt/lkproxy/key.pem" ]; then
        echo -e "${YELLOW}Gerando certificado auto-assinado...${NC}"
        openssl req -x509 -newkey rsa:2048 -keyout /opt/lkproxy/key.pem \
            -out /opt/lkproxy/cert.pem -days 365 -nodes \
            -subj "/CN=lkproxy/O=LKProxy/C=BR" 2>/dev/null
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
        box_top
        box_line "${GREEN}${BOLD}ATIVO NA PORTA 443${NC}"
        box_line "${GREEN}xHTTP_SSH + SSL TUNNEL${NC}"
        box_bottom
        echo ""
        box_top
        box_line "${YELLOW}${BOLD}SocksRevive (xHTTP SplitHTTP):${NC}"
        box_line "  Server: IP deste servidor"
        box_line "  Port: 443"
        box_line "  SNI: qualquer domínio (trust-all)"
        box_line "  XHTTP Path: /ssh"
        box_line "  XHTTP TLS: HABILITADO"
        box_mid
        box_line "${YELLOW}${BOLD}HTTP Injector (SSL Tunnel):${NC}"
        box_line "  Server: IP deste servidor"
        box_line "  Port: 443"
        box_line "  SSL Proxy: HABILITADO"
        box_line "  Payload: default"
        box_bottom
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
Description=LKProxy - Porta ${PORT}
After=network.target

[Service]
Type=simple
ExecStart=${SDPROXY} ${EXTRA_ARGS}
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=/opt/lkproxy

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
Description=LKProxy xHTTP + SSL Tunnel - Porta ${PORT}
After=network.target

[Service]
Type=simple
ExecStart=${LKPROXY_XHTTP} ${EXTRA_ARGS}
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=/opt/lkproxy

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
    box_top
    box_line "${WHITE}${BOLD}Fechar Porta${NC}"
    box_bottom
    echo ""

    show_active_ports_boxed

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
    box_top
    box_line "${WHITE}${BOLD}Reiniciar Porta${NC}"
    box_bottom
    echo ""

    show_active_ports_boxed

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

# Caixa de portas ativas usada em fechar/reiniciar
show_active_ports_boxed() {
    box_top
    show_active_ports
    box_bottom
    echo ""
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
