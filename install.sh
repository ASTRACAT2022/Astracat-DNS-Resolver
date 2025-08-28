#!/bin/bash

# Astracat-DNS-Resolver Installer Script
# Скрипт установки Astracat DNS Resolver от ASTRACAT
# Версия: 1.0

set -e  # Остановить выполнение при любой ошибке

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Константы
DNS_VERSION="1.0"
DNS_PORT="53"
DNS_USER="astracat-dns"
DNS_DIR="/opt/astracat-dns"
DNS_LOG_DIR="/var/log/astracat-dns"
DNS_SERVICE_NAME="astracat-dns"
MIN_GO_VERSION="1.21.0"

# Функции для вывода
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${GREEN}"
    echo "=================================================="
    echo "    Astracat DNS Resolver Installer v${DNS_VERSION}"
    echo "    High-Performance DNS Resolver by ASTRACAT"
    echo "=================================================="
    echo -e "${NC}"
}

# Проверка прав root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Этот скрипт должен быть запущен с правами root"
        print_info "Используйте: sudo $0"
        exit 1
    fi
}

# Проверка версии Go
check_go_version() {
    if ! command -v go &> /dev/null; then
        return 1
    fi
    
    local go_version=$(go version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    local required_version=$MIN_GO_VERSION
    
    if [[ "$(printf '%s\n' "$required_version" "$go_version" | sort -V | head -n1)" != "$required_version" ]]; then
        return 1
    fi
    
    return 0
}

# Установка Go
install_go() {
    print_info "Установка Go ${MIN_GO_VERSION}..."
    
    local go_archive=""
    local go_url="https://golang.org/dl/"
    
    case "$(uname -m)" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv6l)
            ARCH="armv6l"
            ;;
        *)
            print_error "Неподдерживаемая архитектура: $(uname -m)"
            exit 1
            ;;
    esac
    
    go_archive="go${MIN_GO_VERSION}.linux-${ARCH}.tar.gz"
    
    # Удаляем старую версию Go
    if [[ -d "/usr/local/go" ]]; then
        print_info "Удаление старой версии Go..."
        rm -rf /usr/local/go
    fi
    
    # Скачиваем и устанавливаем Go
    cd /tmp
    print_info "Скачивание ${go_archive}..."
    curl -LO "${go_url}${go_archive}" || {
        print_error "Не удалось скачать Go"
        exit 1
    }
    
    print_info "Распаковка Go..."
    tar -C /usr/local -xzf "${go_archive}"
    
    # Добавляем Go в PATH
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    
    print_success "Go ${MIN_GO_VERSION} успешно установлен"
}

# Создание пользователя
create_dns_user() {
    if ! id "$DNS_USER" &>/dev/null; then
        print_info "Создание пользователя $DNS_USER..."
        useradd -r -s /bin/false -d "$DNS_DIR" "$DNS_USER" || true
        print_success "Пользователь $DNS_USER создан"
    else
        print_info "Пользователь $DNS_USER уже существует"
    fi
}

# Создание директорий
create_directories() {
    print_info "Создание директорий..."
    
    mkdir -p "$DNS_DIR"
    mkdir -p "$DNS_LOG_DIR"
    
    chown -R "$DNS_USER:$DNS_USER" "$DNS_DIR" "$DNS_LOG_DIR" 2>/dev/null || {
        chown -R "$DNS_USER" "$DNS_DIR" "$DNS_LOG_DIR"
    }
    
    print_success "Директории созданы"
}

# Клонирование и сборка Astracat DNS Resolver
build_dns_resolver() {
    print_info "Клонирование репозитория Astracat DNS Resolver..."
    
    cd /tmp
    if [[ -d "Astracat-DNS-Resolver" ]]; then
        rm -rf Astracat-DNS-Resolver
    fi
    
    git clone https://github.com/ASTRACAT2022/Astracat-DNS-Resolver.git
    cd Astracat-DNS-Resolver
    
    print_info "Установка Go зависимостей..."
    go mod tidy
    
    print_info "Сборка Astracat DNS Resolver..."
    go build -o astracat-dns .
    
    print_info "Установка исполняемого файла..."
    cp astracat-dns "$DNS_DIR/"
    chmod +x "$DNS_DIR/astracat-dns"
    
    chown -R "$DNS_USER:$DNS_USER" "$DNS_DIR" 2>/dev/null || {
        chown -R "$DNS_USER" "$DNS_DIR"
    }
    
    print_success "Astracat DNS Resolver успешно собран и установлен"
}

# Создание systemd сервиса
create_systemd_service() {
    print_info "Создание systemd сервиса..."
    
    cat > "/etc/systemd/system/$DNS_SERVICE_NAME.service" << EOF
[Unit]
Description=Astracat DNS Resolver
After=network.target
Wants=network.target

[Service]
Type=simple
User=$DNS_USER
Group=$DNS_USER
ExecStart=$DNS_DIR/astracat-dns
WorkingDirectory=$DNS_DIR
Restart=always
RestartSec=5
StandardOutput=append:$DNS_LOG_DIR/astracat-dns.log
StandardError=append:$DNS_LOG_DIR/astracat-dns.log

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DNS_LOG_DIR

# Network settings for port 53
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$DNS_SERVICE_NAME"
    
    print_success "Systemd сервис создан и включен"
}

# Настройка файрвола
configure_firewall() {
    print_info "Настройка файрвола..."
    
    if command -v ufw &> /dev/null; then
        ufw allow "$DNS_PORT/udp" comment "Astracat DNS Resolver"
        ufw allow "$DNS_PORT/tcp" comment "Astracat DNS Resolver"
        print_success "UFW правила добавлены"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port="$DNS_PORT/udp"
        firewall-cmd --permanent --add-port="$DNS_PORT/tcp"
        firewall-cmd --reload
        print_success "Firewalld правила добавлены"
    else
        print_warning "Не удалось определить файрвол. Настройте вручную для порта $DNS_PORT"
    fi
}

# Запуск сервиса
start_service() {
    print_info "Запуск Astracat DNS Resolver сервиса..."
    
    systemctl start "$DNS_SERVICE_NAME"
    
    sleep 2
    
    if systemctl is-active --quiet "$DNS_SERVICE_NAME"; then
        print_success "Astracat DNS Resolver сервис работает"
    else
        print_error "Astracat DNS Resolver сервис не запустился"
    fi
}

# Тестирование DNS сервера
test_dns_server() {
    print_info "Тестирование DNS сервера..."
    
    sleep 3  # Даем время на запуск
    
    if command -v dig &> /dev/null; then
        print_info "Тестирование с помощью dig..."
        if dig @localhost google.com A +short +time=5 >/dev/null 2>&1; then
            print_success "DNS сервер отвечает на запросы"
        else
            print_warning "DNS сервер не отвечает или есть проблемы с сетью"
        fi
    elif command -v nslookup &> /dev/null; then
        print_info "Тестирование с помощью nslookup..."
        if timeout 5 nslookup google.com localhost >/dev/null 2>&1; then
            print_success "DNS сервер отвечает на запросы"
        else
            print_warning "DNS сервер не отвечает или есть проблемы с сетью"
        fi
    else
        print_warning "dig или nslookup не найдены. Пропускаем тест DNS."
    fi
}

# Создание скриптов управления
create_management_scripts() {
    print_info "Создание скриптов управления..."
    
    # Скрипт запуска/остановки
    cat > "$DNS_DIR/dns-ctl.sh" << 'EOF'
#!/bin/bash

SERVICE_NAME="astracat-dns"

case "$1" in
    start)
        sudo systemctl start "$SERVICE_NAME"
        echo "Astracat DNS started"
        ;;
    stop)
        sudo systemctl stop "$SERVICE_NAME"
        echo "Astracat DNS stopped"
        ;;
    restart)
        sudo systemctl restart "$SERVICE_NAME"
        echo "Astracat DNS restarted"
        ;;
    status)
        systemctl status "$SERVICE_NAME"
        ;;
    logs)
        journalctl -u "$SERVICE_NAME" -f
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
EOF

    chmod +x "$DNS_DIR/dns-ctl.sh"
    
    # Создаем символическую ссылку в /usr/local/bin
    if [[ ! -L "/usr/local/bin/astracat-dns-ctl" ]]; then
        ln -s "$DNS_DIR/dns-ctl.sh" "/usr/local/bin/astracat-dns-ctl"
    fi
    
    print_success "Скрипты управления созданы"
}

# Показать информацию после установки
show_post_install_info() {
    print_success "Astracat DNS Resolver успешно установлен!"
    echo
    print_info "Информация об установке:"
    echo "  • Директория установки: $DNS_DIR"
    echo "  • Логи: $DNS_LOG_DIR/astracat-dns.log"
    echo "  • Порт: $DNS_PORT"
    echo "  • Пользователь: $DNS_USER"
    echo
    print_info "Команды управления:"
    echo "  • Запуск: astracat-dns-ctl start"
    echo "  • Остановка: astracat-dns-ctl stop"
    echo "  • Перезапуск: astracat-dns-ctl restart"
    echo "  • Статус: astracat-dns-ctl status"
    echo "  • Логи: astracat-dns-ctl logs"
    echo
    print_info "Тестирование DNS:"
    echo "  • dig @localhost google.com A"
    echo "  • nslookup google.com localhost"
}

# Функция удаления (для --uninstall)
uninstall_dns() {
    print_info "Удаление Astracat DNS Resolver..."
    
    # Остановка сервиса
    systemctl stop "$DNS_SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$DNS_SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/$DNS_SERVICE_NAME.service"
    systemctl daemon-reload
    
    # Удаление файлов
    rm -rf "$DNS_DIR"
    rm -rf "$DNS_LOG_DIR"
    rm -f "/usr/local/bin/astracat-dns-ctl"
    
    # Удаление пользователя
    if id "$DNS_USER" &>/dev/null; then
        userdel "$DNS_USER" 2>/dev/null || true
    fi
    
    print_success "Astracat DNS Resolver удален"
}

# Главная функция
main() {
    # Обработка аргументов
    case "${1:-}" in
        --uninstall)
            print_header
            check_root
            uninstall_dns
            exit 0
            ;;
        --help|-h)
            print_header
            echo "Использование: $0 [ОПЦИИ]"
            echo
            echo "ОПЦИИ:"
            echo "  --uninstall    Удалить Astracat DNS Resolver"
            echo "  --help, -h     Показать эту справку"
            echo
            exit 0
            ;;
    esac
    
    print_header
    
    # Проверки
    check_root
    
    # Проверка и установка Go
    if ! check_go_version; then
        print_warning "Go ${MIN_GO_VERSION}+ не найден или версия устарела"
        install_go
    else
        print_success "Go уже установлен: $(go version)"
    fi
    
    # Установка
    create_dns_user
    create_directories
    build_dns_resolver
    create_systemd_service
    configure_firewall
    create_management_scripts
    start_service
    test_dns_server
    
    # Финальная информация
    show_post_install_info
}

# Запуск главной функции
main "$@"
