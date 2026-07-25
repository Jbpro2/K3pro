#!/bin/bash
# SDProxy Installer - Version v3.1.0

REPO_URL="https://github.com/PedroJbk/BDRProxy.git"
REPO_BRANCH="main"
CMD_NAME="sdproxy"
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
echo -e "${BLUE}${BOLD} ███████╗██████╗ ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗${NC}"
echo -e "${BLUE}${BOLD} ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝${NC}"
echo -e "${BLUE}${BOLD} ███████╗██║  ██║██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ${NC}"
echo -e "${BLUE}${BOLD} ╚════██║██║  ██║██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ${NC}"
echo -e "${BLUE}${BOLD} ███████║██████╔╝██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ${NC}"
echo -e "${BLUE}${BOLD} ╚══════╝╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ${NC}"
echo -e "${BLUE}${BOLD}--------------------------------------------------------------${NC}"
log_info "Iniciando instalação do SDProxy v3.1.0 (🇧🇷)..."

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
rm -rf /tmp/SDProxy_build
git clone --branch "$REPO_BRANCH" "$REPO_URL" /tmp/SDProxy_build > /dev/null 2>&1 || log_error "Falha ao clonar repositório."
cd /tmp/SDProxy_build || log_error "Falha ao acessar diretório."

# --- Etapa 4 ---
show_progress "Compilando (2-5 min)..."
cargo build --release > /tmp/sdproxy_build.log 2>&1
if [ $? -ne 0 ]; then
    cat /tmp/sdproxy_build.log
    log_error "Falha na compilação. Veja logs acima."
fi

# --- Etapa 5 ---
show_progress "Instalando binários..."
mkdir -p /opt/sdproxy

# Parar processos antigos para liberar os arquivos
pkill -f "sdproxy" > /dev/null 2>&1
pkill -f "sdproxy-xhttp" > /dev/null 2>&1
sleep 1

# Copiar com força (-f)
cp -f ./target/release/sdproxy /opt/sdproxy/proxy || log_error "Falha ao copiar sdproxy. Verifique se o disco está cheio."
chmod +x /opt/sdproxy/proxy

if [ -f ./target/release/sdproxy-xhttp ]; then
    cp -f ./target/release/sdproxy-xhttp /opt/sdproxy/proxy-xhttp
    chmod +x /opt/sdproxy/proxy-xhttp
    ln -sf /opt/sdproxy/proxy-xhttp /usr/local/bin/sdproxy-xhttp
fi

# Menu
if [ -f "menu.sh" ]; then
    cp -f menu.sh /opt/sdproxy/menu
    chmod +x /opt/sdproxy/menu
    ln -sf /opt/sdproxy/menu /usr/local/bin/sdproxy
fi

# Certificados
if [ ! -f /opt/sdproxy/cert.pem ]; then
    openssl req -x509 -newkey rsa:2048 -keyout /opt/sdproxy/key.pem -out /opt/sdproxy/cert.pem -days 3650 -nodes -subj "/CN=SDProxy" 2>/dev/null
fi

# --- Etapa 6 ---
show_progress "Limpando..."
rm -rf /tmp/SDProxy_build

# --- Etapa 7 ---
log_success "Instalação concluída com sucesso!"
echo -e "Use o comando ${YELLOW}sdproxy${NC} para abrir o menu."
echo -e "--------------------------------------------------------------"
