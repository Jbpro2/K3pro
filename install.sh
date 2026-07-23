#!/bin/bash
# SDProxy Installer - Version v2.2

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
log_info "Iniciando instalação do SDProxy v2.3..."

# --- Etapa 1 ---
show_progress "Atualizando repositórios e instalando dependências..."
apt update -y > /dev/null 2>&1 || log_error "Falha ao atualizar repositórios."
apt install -y curl build-essential git lsb-release libssl-dev pkg-config openssl openssh-server > /dev/null 2>&1 || log_error "Falha ao instalar dependências."

# --- Etapa 2 ---
show_progress "Verificando e instalando o Rust..."
if ! command -v cargo &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y > /dev/null 2>&1
    source "$HOME/.cargo/env" || log_error "Falha ao configurar o ambiente Rust."
else
    log_info "Rust já está instalado."
    source "$HOME/.cargo/env"
fi

# --- Etapa 3 ---
show_progress "Baixando o código fonte do SDProxy..."
rm -rf /root/SDProxy
git clone --branch "$REPO_BRANCH" "$REPO_URL" /root/SDProxy > /dev/null 2>&1 || log_error "Falha ao clonar o repositório."
cd /root/SDProxy || log_error "Falha ao entrar no diretório do projeto."

# --- Etapa 4 ---
show_progress "Compilando SDProxy + xHTTP (pode levar 2-5 minutos)..."
cargo build --release > /tmp/sdproxy_build.log 2>&1
if [ $? -ne 0 ]; then
    log_error "Falha na compilação. Verifique /tmp/sdproxy_build.log"
fi

# --- Etapa 5 ---
show_progress "Instalando binários e configurando o sistema..."
mkdir -p /opt/sdproxy || log_error "Falha ao criar diretório /opt/sdproxy."

# Gerar certificados TLS para xHTTP
mkdir -p /opt/sdproxy
if [ ! -f /opt/sdproxy/cert.pem ] || [ ! -f /opt/sdproxy/key.pem ]; then
    echo -e "${CYAN}  Gerando certificados TLS auto-assinados...${NC}"
    openssl req -x509 -newkey rsa:2048 -keyout /opt/sdproxy/key.pem \
        -out /opt/sdproxy/cert.pem -days 3650 -nodes \
        -subj "/CN=SDProxy" 2>/dev/null
    if [ -f /opt/sdproxy/cert.pem ] && [ -f /opt/sdproxy/key.pem ]; then
        log_info "Certificados TLS gerados em /opt/sdproxy/"
    else
        log_error "Falha ao gerar certificados TLS!"
    fi
else
    log_info "Certificados TLS ja existem em /opt/sdproxy/"
fi
chmod 644 /opt/sdproxy/cert.pem
chmod 600 /opt/sdproxy/key.pem

# Copiar binários
cp ./target/release/sdproxy /opt/sdproxy/proxy 2>/dev/null || log_error "Falha ao copiar sdproxy."
chmod +x /opt/sdproxy/proxy

if [ -f ./target/release/sdproxy-xhttp ]; then
    cp ./target/release/sdproxy-xhttp /opt/sdproxy/proxy-xhttp
    chmod +x /opt/sdproxy/proxy-xhttp
    ln -sf /opt/sdproxy/proxy-xhttp /usr/local/bin/sdproxy-xhttp
    log_info "sdproxy-xhttp instalado"
fi

# Menu
if [ -f "menu.sh" ]; then
    cp menu.sh /opt/sdproxy/menu || log_error "Falha ao copiar menu."
    chmod +x /opt/sdproxy/menu || log_error "Falha ao dar permissão ao menu."
    ln -sf /opt/sdproxy/menu /usr/local/bin/sdproxy
else
    ln -sf /opt/sdproxy/proxy /usr/local/bin/sdproxy
fi

# --- Etapa 6 ---
show_progress "Limpando arquivos temporários..."
rm -rf /root/SDProxy
rm -f /tmp/sdproxy_build.log

# --- Etapa 7 ---
log_success "Instalação do SDProxy v2.3 concluída!"
echo ""
echo -e "${BLUE}${BOLD}  Binários:${NC}"
echo -e "  /opt/sdproxy/proxy       → Proxy BSProxy (80, 8080, 443)"
echo -e "  /opt/sdproxy/proxy-xhttp → xHTTP SplitHTTP + SSL Tunnel (443)"
echo ""
echo -e "${BLUE}${BOLD}  Comandos:${NC}"
echo -e "  sdproxy                  → Menu (opção [04] = xHTTP)"
echo -e "  sdproxy-xhttp            → Inicia xHTTP direto"
echo ""
echo -e "${BLUE}${BOLD}  Config SocksRevive:${NC}"
echo -e "  Server: IP do servidor"
echo -e "  Port:   443"
echo -e "  SNI:    google.com"
echo -e "  Path:   /ssh"
echo -e "  TLS:    Habilitado"
echo ""
echo -e "${BLUE}${BOLD}--------------------------------------------------------------${NC}"
echo -e "${BLUE}${BOLD}  SDProxy v2.2 instalado com sucesso!${NC}"
echo -e "${BLUE}${BOLD}--------------------------------------------------------------${NC}"
