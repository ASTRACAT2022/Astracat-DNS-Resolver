#!/bin/bash

# DNS-g Installer Script
# Скрипт установки DNS сервера DNS-g от ASTRACAT
# Версия: 1.0
# Автор: ASTRACAT

set -e  # Остановить выполнение при любой ошибке

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Константы
DNS_G_VERSION="1.0"
DNS_G_PORT="5454"
DNS_G_USER="dns-g"
DNS_G_DIR="/opt/dns-g"
DNS_G_CONFIG_DIR="/etc/dns-g"
DNS_G_LOG_DIR="/var/log/dns-g"
DNS_G_SERVICE_NAME="dns-g"
MIN_GO_VERSION="1.25.0"

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
    echo "    DNS-g Installer v${DNS_G_VERSION}"
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

# Определение операционной системы
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [[ -f /etc/redhat-release ]]; then
        OS="Red Hat Enterprise Linux"
        VER=$(cat /etc/redhat-release | grep -oE '[0-9]+\.[0-9]+')
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macOS"
        VER=$(sw_vers -productVersion)
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    print_info "Обнаружена ОС: $OS $VER"
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
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        go_archive="go${MIN_GO_VERSION}.darwin-${ARCH}.tar.gz"
    else
        go_archive="go${MIN_GO_VERSION}.linux-${ARCH}.tar.gz"
    fi
    
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

# Установка зависимостей системы
install_system_dependencies() {
    print_info "Установка системных зависимостей..."
    
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        apt-get update
        apt-get install -y curl wget git build-essential
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Rocky"* ]]; then
        yum update -y
        yum groupinstall -y "Development Tools"
        yum install -y curl wget git
    elif [[ "$OS" == *"Fedora"* ]]; then
        dnf update -y
        dnf groupinstall -y "Development Tools"
        dnf install -y curl wget git
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if ! command -v brew &> /dev/null; then
            print_info "Установка Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        fi
        brew install curl wget git
    else
        print_warning "Неизвестная ОС. Пропускаем установку зависимостей."
    fi
    
    print_success "Системные зависимости установлены"
}

# Создание пользователя dns-g
create_dns_user() {
    if ! id "$DNS_G_USER" &>/dev/null; then
        print_info "Создание пользователя $DNS_G_USER..."
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            dscl . -create /Users/$DNS_G_USER
            dscl . -create /Users/$DNS_G_USER UserShell /bin/false
            dscl . -create /Users/$DNS_G_USER RealName "DNS-g Service User"
            dscl . -create /Users/$DNS_G_USER UniqueID 502
            dscl . -create /Users/$DNS_G_USER PrimaryGroupID 502
        else
            # Linux
            useradd -r -s /bin/false -d "$DNS_G_DIR" "$DNS_G_USER" || true
        fi
        print_success "Пользователь $DNS_G_USER создан"
    else
        print_info "Пользователь $DNS_G_USER уже существует"
    fi
}

# Создание директорий
create_directories() {
    print_info "Создание директорий..."
    
    mkdir -p "$DNS_G_DIR"
    mkdir -p "$DNS_G_CONFIG_DIR"
    mkdir -p "$DNS_G_LOG_DIR"
    
    chown -R "$DNS_G_USER:$DNS_G_USER" "$DNS_G_DIR" "$DNS_G_LOG_DIR" 2>/dev/null || {
        chown -R "$DNS_G_USER" "$DNS_G_DIR" "$DNS_G_LOG_DIR"
    }
    
    print_success "Директории созданы"
}

# Клонирование и сборка DNS-g
build_dns_g() {
    print_info "Клонирование репозитория DNS-g..."
    
    cd /tmp
    if [[ -d "dns-g" ]]; then
        rm -rf dns-g
    fi
    
    git clone https://github.com/ASTRACAT2022/dns-g.git
    cd dns-g
    
    print_info "Установка Go зависимостей..."
    go mod tidy
    
    print_info "Сборка DNS-g..."
    go build -o dns_resolver main.go
    
    print_info "Установка исполняемого файла..."
    cp dns_resolver "$DNS_G_DIR/"
    cp README.md "$DNS_G_DIR/"
    cp test_dns_resolver.sh "$DNS_G_DIR/"
    chmod +x "$DNS_G_DIR/dns_resolver"
    chmod +x "$DNS_G_DIR/test_dns_resolver.sh"
    
    chown -R "$DNS_G_USER:$DNS_G_USER" "$DNS_G_DIR" 2>/dev/null || {
        chown -R "$DNS_G_USER" "$DNS_G_DIR"
    }
    
    print_success "DNS-g успешно собран и установлен"
}

# Создание конфигурационного файла
create_config() {
    print_info "Создание конфигурационного файла..."
    
    cat > "$DNS_G_CONFIG_DIR/dns-g.conf" << EOF
# DNS-g Configuration File
# Port to listen on
PORT=$DNS_G_PORT

# Cache TTL in minutes
CACHE_TTL=5

# Log level (DEBUG, INFO, WARN, ERROR)
LOG_LEVEL=INFO

# Log file path
LOG_FILE=$DNS_G_LOG_DIR/dns-g.log

# Maximum cache entries
MAX_CACHE_ENTRIES=10000

# DNS resolver timeout in seconds
RESOLVER_TIMEOUT=10
EOF

    chown "$DNS_G_USER:$DNS_G_USER" "$DNS_G_CONFIG_DIR/dns-g.conf" 2>/dev/null || {
        chown "$DNS_G_USER" "$DNS_G_CONFIG_DIR/dns-g.conf"
    }
    
    print_success "Конфигурационный файл создан: $DNS_G_CONFIG_DIR/dns-g.conf"
}

# Создание systemd сервиса
create_systemd_service() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        create_launchd_service
        return
    fi
    
    print_info "Создание systemd сервиса..."
    
    cat > "/etc/systemd/system/$DNS_G_SERVICE_NAME.service" << EOF
[Unit]
Description=DNS-g High-Performance DNS Resolver
After=network.target
Wants=network.target

[Service]
Type=simple
User=$DNS_G_USER
Group=$DNS_G_USER
ExecStart=$DNS_G_DIR/dns_resolver
Restart=always
RestartSec=5
StandardOutput=append:$DNS_G_LOG_DIR/dns-g.log
StandardError=append:$DNS_G_LOG_DIR/dns-g.log

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$DNS_G_LOG_DIR

# Network settings
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$DNS_G_SERVICE_NAME"
    
    print_success "Systemd сервис создан и включен"
}

# Создание launchd сервиса для macOS
create_launchd_service() {
    print_info "Создание launchd сервиса для macOS..."
    
    cat > "/Library/LaunchDaemons/com.astracat.dns-g.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.astracat.dns-g</string>
    <key>ProgramArguments</key>
    <array>
        <string>$DNS_G_DIR/dns_resolver</string>
    </array>
    <key>UserName</key>
    <string>$DNS_G_USER</string>
    <key>GroupName</key>
    <string>$DNS_G_USER</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$DNS_G_LOG_DIR/dns-g.log</string>
    <key>StandardErrorPath</key>
    <string>$DNS_G_LOG_DIR/dns-g.log</string>
</dict>
</plist>
EOF

    chown root:wheel "/Library/LaunchDaemons/com.astracat.dns-g.plist"
    chmod 644 "/Library/LaunchDaemons/com.astracat.dns-g.plist"
    
    print_success "Launchd сервис создан"
}

# Настройка файрвола
configure_firewall() {
    print_info "Настройка файрвола..."
    
    if command -v ufw &> /dev/null; then
        ufw allow "$DNS_G_PORT/udp" comment "DNS-g resolver"
        print_success "UFW правило добавлено"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port="$DNS_G_PORT/udp"
        firewall-cmd --reload
        print_success "Firewalld правило добавлено"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        print_info "macOS: Настройте файрвол вручную для порта $DNS_G_PORT/UDP"
    else
        print_warning "Не удалось определить файрвол. Настройте вручную для порта $DNS_G_PORT/UDP"
    fi
}

# Запуск сервиса
start_service() {
    print_info "Запуск DNS-g сервиса..."
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        launchctl load "/Library/LaunchDaemons/com.astracat.dns-g.plist"
        print_success "DNS-g сервис запущен через launchd"
    else
        systemctl start "$DNS_G_SERVICE_NAME"
        print_success "DNS-g сервис запущен через systemd"
    fi
    
    sleep 2
    
    # Проверка статуса
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if launchctl list | grep -q "com.astracat.dns-g"; then
            print_success "DNS-g сервис работает"
        else
            print_error "DNS-g сервис не запустился"
        fi
    else
        if systemctl is-active --quiet "$DNS_G_SERVICE_NAME"; then
            print_success "DNS-g сервис работает"
        else
            print_error "DNS-g сервис не запустился"
        fi
    fi
}

# Тестирование DNS сервера
test_dns_server() {
    print_info "Тестирование DNS сервера..."
    
    sleep 3  # Даем время на запуск
    
    if command -v dig &> /dev/null; then
        print_info "Тестирование с помощью dig..."
        if dig @localhost -p "$DNS_G_PORT" google.com A +short +time=5 >/dev/null 2>&1; then
            print_success "DNS сервер отвечает на запросы"
        else
            print_warning "DNS сервер не отвечает или есть проблемы с сетью"
        fi
    elif command -v nslookup &> /dev/null; then
        print_info "Тестирование с помощью nslookup..."
        if timeout 5 nslookup google.com localhost -port="$DNS_G_PORT" >/dev/null 2>&1; then
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
    cat > "$DNS_G_DIR/dns-g-ctl.sh" << 'EOF'
#!/bin/bash

SERVICE_NAME="dns-g"
LAUNCHD_PLIST="/Library/LaunchDaemons/com.astracat.dns-g.plist"

case "$1" in
    start)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sudo launchctl load "$LAUNCHD_PLIST"
            echo "DNS-g started"
        else
            sudo systemctl start "$SERVICE_NAME"
            echo "DNS-g started"
        fi
        ;;
    stop)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sudo launchctl unload "$LAUNCHD_PLIST"
            echo "DNS-g stopped"
        else
            sudo systemctl stop "$SERVICE_NAME"
            echo "DNS-g stopped"
        fi
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            if launchctl list | grep -q "com.astracat.dns-g"; then
                echo "DNS-g is running"
            else
                echo "DNS-g is not running"
            fi
        else
            systemctl status "$SERVICE_NAME"
        fi
        ;;
    logs)
        if [[ "$OSTYPE" == "darwin"* ]]; then
            tail -f /var/log/dns-g/dns-g.log
        else
            journalctl -u "$SERVICE_NAME" -f
        fi
        ;;
    test)
        /opt/dns-g/test_dns_resolver.sh
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|test}"
        exit 1
        ;;
esac
EOF

    chmod +x "$DNS_G_DIR/dns-g-ctl.sh"
    
    # Создаем символическую ссылку в /usr/local/bin
    if [[ ! -L "/usr/local/bin/dns-g-ctl" ]]; then
        ln -s "$DNS_G_DIR/dns-g-ctl.sh" "/usr/local/bin/dns-g-ctl"
    fi
    
    print_success "Скрипты управления созданы"
}

# Показать информацию после установки
show_post_install_info() {
    print_success "DNS-g успешно установлен!"
    echo
    print_info "Информация об установке:"
    echo "  • Директория установки: $DNS_G_DIR"
    echo "  • Конфигурация: $DNS_G_CONFIG_DIR/dns-g.conf"
    echo "  • Логи: $DNS_G_LOG_DIR/dns-g.log"
    echo "  • Порт: $DNS_G_PORT"
    echo "  • Пользователь: $DNS_G_USER"
    echo
    print_info "Команды управления:"
    echo "  • Запуск: dns-g-ctl start"
    echo "  • Остановка: dns-g-ctl stop"
    echo "  • Перезапуск: dns-g-ctl restart"
    echo "  • Статус: dns-g-ctl status"
    echo "  • Логи: dns-g-ctl logs"
    echo "  • Тест: dns-g-ctl test"
    echo
    print_info "Тестирование DNS:"
    echo "  • dig @localhost -p $DNS_G_PORT google.com A"
    echo "  • nslookup google.com localhost -port=$DNS_G_PORT"
    echo
    print_info "Конфигурация клиентов:"
    echo "  • Добавьте 127.0.0.1:$DNS_G_PORT в настройки DNS"
    echo "  • Или используйте как upstream DNS сервер"
}

# Функция удаления (для --uninstall)
uninstall_dns_g() {
    print_info "Удаление DNS-g..."
    
    # Остановка сервиса
    if [[ "$OSTYPE" == "darwin"* ]]; then
        launchctl unload "/Library/LaunchDaemons/com.astracat.dns-g.plist" 2>/dev/null || true
        rm -f "/Library/LaunchDaemons/com.astracat.dns-g.plist"
    else
        systemctl stop "$DNS_G_SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$DNS_G_SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/$DNS_G_SERVICE_NAME.service"
        systemctl daemon-reload
    fi
    
    # Удаление файлов
    rm -rf "$DNS_G_DIR"
    rm -rf "$DNS_G_CONFIG_DIR"
    rm -rf "$DNS_G_LOG_DIR"
    rm -f "/usr/local/bin/dns-g-ctl"
    
    # Удаление пользователя
    if id "$DNS_G_USER" &>/dev/null; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            dscl . -delete "/Users/$DNS_G_USER" 2>/dev/null || true
        else
            userdel "$DNS_G_USER" 2>/dev/null || true
        fi
    fi
    
    print_success "DNS-g удален"
}

# Главная функция
main() {
    # Обработка аргументов
    case "${1:-}" in
        --uninstall)
            print_header
            check_root
            uninstall_dns_g
            exit 0
            ;;
        --help|-h)
            print_header
            echo "Использование: $0 [ОПЦИИ]"
            echo
            echo "ОПЦИИ:"
            echo "  --uninstall    Удалить DNS-g"
            echo "  --help, -h     Показать эту справку"
            echo
            exit 0
            ;;
    esac
    
    print_header
    
    # Проверки
    check_root
    detect_os
    
    # Проверка и установка Go
    if ! check_go_version; then
        print_warning "Go ${MIN_GO_VERSION}+ не найден или версия устарела"
        install_system_dependencies
        install_go
    else
        print_success "Go уже установлен: $(go version)"
    fi
    
    # Установка
    create_dns_user
    create_directories
    build_dns_g
    create_config
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
