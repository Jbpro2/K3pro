#!/bin/bash

# ============================================
# Mpro Menu - Free v5
# ============================================

LKPROXY="/opt/mpro/proxy"
LKPROXY_XHTTP="/opt/mpro/proxy-xhttp"
LKPROXY_INTEGRATED="/opt/mpro/proxy-integrated"
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

show_banner() {
echo -e "${PURPLE}${BOLD} ███╗   ███╗██████╗ ██████╗  ██████╗ ${NC}"
echo -e "${PURPLE}${BOLD} ████╗ ████║██╔══██╗██╔══██╗██╔═══██╗${NC}"
echo -e "${BLUE}${BOLD} ██╔████╔██║██████╔╝██████╔╝██║   ██║${NC}"
echo -e "${BLUE}${BOLD} ██║╚██╔╝██║██╔═══╝ ██╔══██╗██║   ██║${NC}"
echo -e "${PURPLE}${BOLD} ██║ ╚═╝ ██║██║     ██║  ██║╚██████╔╝${NC}"
echo -e "${BLUE}${BOLD} ╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ${NC}"
echo -e "${BLUE}${BOLD}         F R E E   V E R S I O N       ${NC}"
echo -e "${BLUE}${BOLD}----------------------------------------${NC}"
}

show_active_ports() {
    ACTIVE=""
    XHTTP_ACTIVE=false
    INTEGRATED_ACTIVE=false

    for service_file in ${SYSTEMD_DIR}/proxy-*.service; do
        if [ -f "$service_file" ]; then
            NAME=$(basename "$service_file" .service | sed 's/proxy-//')
            if systemctl is-active --quiet "proxy-${NAME}.service" 2>/dev/null; then
                if [ "$NAME" = "443" ]; then
                    XHTTP_ACTIVE=true
                elif [ "$NAME" = "integrated" ]; then
                    INTEGRATED_ACTIVE=true
                else
                    ACTIVE="$ACTIVE $NAME"
                fi
            fi
        fi
    done

    local ports_str=""
    if [ -n "$ACTIVE" ]; then
        ports_str="${YELLOW}${ACTIVE# }${NC}"
    fi
    if [ "$XHTTP_ACTIVE" = true ]; then
        ports_str="${ports_str}${ports_str:+ }${YELLOW}443${NC}"
    fi
    if [ "$INTEGRATED_ACTIVE" = true ]; then
        ports_str="${ports_str}${ports_str:+ }${GREEN}INTEGRADO${NC}"
    fi
    if [ -z "$ports_str" ]; then
        ports_str="${RED}nenhuma${NC}"
    fi

    box_line "${YELLOW}Porta(s) ativa(s):${NC} ${ports_str}"
}

create_service() {
    local PORT=$1
    local HTTPS=$2
    local STATUS=$3
    local SSH_ONLY=$4
    local SERVICE_FILE="${SYSTEMD_DIR}/proxy-${PORT}.service"
    EXTRA_ARGS="-p ${PORT}"
    [[ -n "$STATUS" ]] && EXTRA_ARGS="${EXTRA_ARGS} -s ${STATUS}"
    [[ "$HTTPS" == "s" ]] && EXTRA_ARGS="${EXTRA_ARGS} -t"
    [[ "$SSH_ONLY" == "s" ]] && EXTRA_ARGS="${EXTRA_ARGS} -ssh"
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Mpro - Porta ${PORT}
After=network.target
[Service]
Type=simple
ExecStart=${LKPROXY} ${EXTRA_ARGS}
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=/opt/mpro
[Install]
WantedBy=multi-user.target
EOF
}

open_port() {
    clear
    show_banner
    echo ""
    box_top
    box_line "${WHITE}${BOLD}Abrir Porta${NC}"
    box_mid
    box_line "${WHITE}Portas padrão: 80, 8080, 8880, 3128${NC}"
    box_line "${YELLOW}Porta 443: use opção [04] XHTTP INTEGRADO${NC}"
    box_bottom
    echo ""
    read -p "Porta: " PORT
    [[ -z "$PORT" ]] && return
    if systemctl is-active --quiet "proxy-${PORT}.service" 2>/dev/null; then
        echo -e "${RED}Porta ${PORT} já está em uso!${NC}"; sleep 2; return
    fi
    read -p "Habilitar o HTTPS? (s/n): " HTTPS
    read -p "Status HTTP (Padrão: @Mpro): " STATUS
    [[ -z "$STATUS" ]] && STATUS="@Mpro"
    read -p "Habilitar somente SSH? (s/n): " SSH_ONLY
    mkdir -p /opt/mpro
    create_service "$PORT" "$HTTPS" "$STATUS" "$SSH_ONLY"
    systemctl daemon-reload
    systemctl enable "proxy-${PORT}.service" 2>/dev/null
    systemctl start "proxy-${PORT}.service" 2>/dev/null
    sleep 2
    read -p "Enter pra continuar..."
}

open_integrated() {
    clear
    echo -e "${CYAN}+--------------------------------------------------------+${NC}"
    echo -e "${CYAN}+--------------------------------------------------------+${NC}"
    echo -e "${WHITE}|  CONFIGURACOES ATUAIS                                  |${NC}"
    echo -e "${CYAN}+--------------------------------------------------------+${NC}"
    echo -e "${WHITE}|  Porta: 8000                                           |${NC}"
    echo -e "${WHITE}|  Sub-rede: 10.10.0.0/16                                |${NC}"
    echo -e "${WHITE}|  Interface TUN: tun0                                   |${NC}"
    echo -e "${WHITE}|  Protocolos: tcp:8000,udp:8000,quic:8001               |${NC}"
    echo -e "${CYAN}+--------------------------------------------------------+${NC}"
    read -p "Porta (Enter para manter [8000]): " PORT
    [[ -z "$PORT" ]] && PORT="8000"
    read -p "Sub-rede CIDR (Enter para manter [10.10.0.0/16]): " SUBNET
    [[ -z "$SUBNET" ]] && SUBNET="10.10.0.0/16"
    read -p "Interface TUN (Enter para manter [tun0]): " TUN
    [[ -z "$TUN" ]] && TUN="tun0"
    read -p "Deseja ativar UDP na mesma porta? (s/N) " ENABLE_UDP
    UDP_ARG=""
    [[ "$ENABLE_UDP" == "s" || "$ENABLE_UDP" == "S" ]] && UDP_ARG="--udp"
    read -p "Deseja ativar QUIC? (s/N) " ENABLE_QUIC
    QUIC_ARG=""
    if [[ "$ENABLE_QUIC" == "s" || "$ENABLE_QUIC" == "S" ]]; then
        read -p "Porta para QUIC (Enter para 8001): " QPORT
        [[ -z "$QPORT" ]] && QPORT="8001"
        QUIC_ARG="--quic --quic-port $QPORT"
    fi
    read -p "Status HTTP (Padrão: @Mpro): " STATUS
    [[ -z "$STATUS" ]] && STATUS="@Mpro"
    read -p "Porta SSH backend (Padrão: 22): " SSH_PORT
    [[ -z "$SSH_PORT" ]] && SSH_PORT="22"
    mkdir -p /opt/mpro
    if [ ! -f "/opt/mpro/cert.pem" ]; then
        openssl req -x509 -newkey rsa:2048 -keyout /opt/mpro/key.pem -out /opt/mpro/cert.pem -days 365 -nodes -subj "/CN=mpro" 2>/dev/null
    fi
    cat > "${SYSTEMD_DIR}/proxy-integrated.service" << EOF
[Unit]
Description=Mpro Integrated
After=network.target
[Service]
Type=simple
ExecStart=${LKPROXY_INTEGRATED} -p ${PORT} -s ${STATUS} --ssh-port ${SSH_PORT} --tun ${TUN} --subnet ${SUBNET} ${UDP_ARG} ${QUIC_ARG}
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=/opt/mpro
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable proxy-integrated.service 2>/dev/null
    systemctl start proxy-integrated.service 2>/dev/null
    sleep 2
    echo "Servidor protocolo iniciado com sucesso!"
    read -p "Pressione Enter para continuar..."
}

restart_port() {
    clear
    show_banner
    echo ""
    box_top
    show_active_ports
    box_bottom
    echo ""
    read -p "Porta (ou integrated): " PORT
    [[ -z "$PORT" ]] && return
    systemctl restart "proxy-${PORT}.service" 2>/dev/null
    echo -e "${GREEN}Porta ${PORT} reiniciada!${NC}"
    sleep 2
}

close_port() {
    clear
    show_banner
    echo ""
    box_top
    show_active_ports
    box_bottom
    echo ""
    read -p "Porta (ou 'integrated'): " PORT
    [[ -z "$PORT" ]] && return
    systemctl stop "proxy-${PORT}.service" 2>/dev/null
    systemctl disable "proxy-${PORT}.service" 2>/dev/null
    rm -f "${SYSTEMD_DIR}/proxy-${PORT}.service"
    systemctl daemon-reload
    echo -e "${GREEN}Porta ${PORT} fechada!${NC}"
    sleep 2
}

show_menu() {
    clear
    show_banner
    echo ""
    box_top
    box_line "${WHITE}${BOLD}Mpro Menu Free v2.3${NC}"
    box_mid
    show_active_ports
    box_mid
    box_line "${WHITE}[01]${NC} - ABRIR PORTA"
    box_line "${WHITE}[02]${NC} - FECHAR PORTA"
    box_line "${WHITE}[03]${NC} - REINICIAR PORTA"
    box_line "${BLUE}[04]${NC} - XHTTP + PROTOCOLO INTEGRADO (DTUNNEL/XHTTP)"
    box_line ""
    box_line "${WHITE}[00]${NC} - SAIR"
    box_bottom
    echo ""
    echo -n "Escolha uma opção: "
}

while true; do
    show_menu
    read OPTION
    case $OPTION in
        01|1) open_port ;;
        02|2) close_port ;;
        03|3) restart_port ;;
        04|4) open_integrated ;;
        00|0) exit 0 ;;
        *) sleep 1 ;;
    esac
done
