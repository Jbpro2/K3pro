#!/bin/bash
# LKProxy Installer - Version v3.1.0

REPO_URL="https://github.com/Lacasx1/Mpro.git"
REPO_BRANCH="main"
CMD_NAME="lkproxy"
TOTAL_STEPS=7

CURRENT_STEP=0

# --- Cores e Estilos ---
GREEN="\033[0;32m"
BLUE="\033[0;34m"
RED="\033[0;31m"
NC="\033[0m"
BOLD="\033[1m"

log_info() {
    echo -e "${BLUE}${BOLD}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}${BOLD}[SUCESSO]${NC} $1"
}

log_error() {
    echo -e "${RED}${BOLD}[ERRO]${NC} $1"
    exit 1
}

show_progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    PERCENT=$((CURRENT_STEP * 100 / TOTAL_STEPS))
    log_info "${PERCENT}% - $1"
}

# --- Verificação de Root ---
if [ "$EUID" -ne 0 ]; then
    log_error "Este script precisa ser executado como ROOT."
fi

clear
echo -e "${PURPLE}${BOLD} ██╗     ██╗  ██╗██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗${NC}"
echo -e "${PURPLE}${BOLD} ██║     ██║ ██╔╝██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝${NC}"
echo -e "${BLUE}${BOLD} ██║     █████╔╝ ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ${NC}"
echo -e "${BLUE}${BOLD} ██║     ██╔═██╗ ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ${NC}"
echo -e "${PURPLE}${BOLD} ███████╗██║  ██╗██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ${NC}"
echo -e "${BLUE}${BOLD} ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ${NC}"
echo -e "${BLUE}${BOLD}--------------------------------------------------------------${NC}"
log_info "Iniciando instalação do LKProxy v3.1.0 (🇧🇷)..."

# --- Etapa 1 ---
show_progress "Atualizando dependências..."
apt update -y > /dev/null 2>&1
apt install -y curl build-essential git libssl-dev pkg-config openssl > /dev/null 2>&1

# --- Etapa 2 ---
show_progress "Verificando Rust..."
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1
    source "$HOME/.cargo/env"
else
    source "$HOME/.cargo/env"
fi

# --- Etapa 3 ---
show_progress "Baixando código fonte..."
rm -rf /tmp/LKProxy_build
git clone --branch "$REPO_BRANCH" "$REPO_URL" /tmp/LKProxy_build > /dev/null 2>&1 || log_error "Falha ao clonar repositório."
cd /tmp/LKProxy_build || log_error "Falha ao acessar diretório."

# --- Etapa 4 ---
show_progress "Compilando (2-5 min)..."
cargo build --release > /tmp/lkproxy_build.log 2>&1
if [ $? -ne 0 ]; then
    cat /tmp/lkproxy_build.log
    log_error "Falha na compilação. Veja logs acima."
fi

# --- Etapa 5 ---
show_progress "Instalando binários..."
mkdir -p /opt/lkproxy

# Parar processos antigos para liberar os arquivos
pkill -f "lkproxy" > /dev/null 2>&1
pkill -f "lkproxy-xhttp" > /dev/null 2>&1
sleep 1

# Copiar com força (-f)
cp -f ./target/release/lkproxy /opt/lkproxy/proxy || log_error "Falha ao copiar lkproxy. Verifique se o disco está cheio."
chmod +x /opt/lkproxy/proxy

if [ -f ./target/release/lkproxy-xhttp ]; then
    cp -f ./target/release/lkproxy-xhttp /opt/lkproxy/proxy-xhttp
    chmod +x /opt/lkproxy/proxy-xhttp
    ln -sf /opt/lkproxy/proxy-xhttp /usr/local/bin/lkproxy-xhttp
fi

if [ -f ./target/release/lkproxy-integrated ]; then
    cp -f ./target/release/lkproxy-integrated /opt/lkproxy/proxy-integrated
    chmod +x /opt/lkproxy/proxy-integrated
    ln -sf /opt/lkproxy/proxy-integrated /usr/local/bin/lkproxy-integrated
fi

# Menu
if [ -f "menu.sh" ]; then
    cp -f menu.sh /opt/lkproxy/menu
    chmod +x /opt/lkproxy/menu
    ln -sf /opt/lkproxy/menu /usr/local/bin/lkproxy
fi

# Certificados
if [ ! -f /opt/lkproxy/cert.pem ]; then
    openssl req -x509 -newkey rsa:2048 -keyout /opt/lkproxy/key.pem -out /opt/lkproxy/cert.pem -days 3650 -nodes -subj "/CN=LKProxy" 2>/dev/null
fi

# --- Etapa 6 ---
show_progress "Limpando..."
rm -rf /tmp/LKProxy_build

# --- Etapa 7 ---
log_success "Instalação concluída com sucesso!"
echo -e "Use o comando ${YELLOW}lkproxy${NC} para abrir o menu."
echo -e "--------------------------------------------------------------"
