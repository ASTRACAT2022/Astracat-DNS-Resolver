# Установка DNS-g

Автоматический инсталлятор для высокопроизводительного DNS сервера DNS-g от ASTRACAT.

## Быстрая установка

```bash
# Скачать и запустить установщик
curl -sSL https://raw.githubusercontent.com/ASTRACAT2022/dns-g/main/install.sh | sudo bash

# Или клонировать репозиторий и запустить локально
git clone https://github.com/ASTRACAT2022/dns-g.git
cd dns-g
sudo ./install.sh
```

## Поддерживаемые системы

- **Linux**: Ubuntu, Debian, CentOS, RHEL, Rocky Linux, Fedora
- **macOS**: 10.15+ (Catalina и новее)
- **Архитектуры**: x86_64 (amd64), ARM64, ARMv6

## Требования

- Права администратора (root/sudo)
- Интернет соединение для скачивания зависимостей
- Минимум 100MB свободного места на диске

## Что делает установщик

1. **Проверка системы**
   - Определение ОС и архитектуры
   - Проверка прав доступа

2. **Установка зависимостей**
   - Go 1.25.0+ (если не установлен)
   - Системные утилиты (curl, wget, git)

3. **Создание инфраструктуры**
   - Пользователь `dns-g`
   - Директории `/opt/dns-g`, `/etc/dns-g`, `/var/log/dns-g`

4. **Сборка и установка**
   - Клонирование исходного кода
   - Компиляция DNS сервера
   - Установка исполняемых файлов

5. **Настройка системного сервиса**
   - systemd сервис (Linux)
   - launchd сервис (macOS)
   - Автозапуск при загрузке системы

6. **Конфигурация безопасности**
   - Настройка файрвола
   - Ограничение привилегий сервиса

## Параметры установки

```bash
# Справка
sudo ./install.sh --help

# Удаление DNS-g
sudo ./install.sh --uninstall
```

## Структура после установки

```
/opt/dns-g/
├── dns_resolver          # Основной исполняемый файл
├── dns-g-ctl.sh         # Скрипт управления
├── test_dns_resolver.sh # Тестовый скрипт
└── README.md            # Документация

/etc/dns-g/
└── dns-g.conf          # Конфигурационный файл

/var/log/dns-g/
└── dns-g.log           # Логи сервиса
```

## Управление сервисом

После установки доступны следующие команды:

```bash
# Управление сервисом
dns-g-ctl start    # Запуск
dns-g-ctl stop     # Остановка  
dns-g-ctl restart  # Перезапуск
dns-g-ctl status   # Статус
dns-g-ctl logs     # Просмотр логов
dns-g-ctl test     # Тестирование

# Альтернативно через systemctl (Linux)
sudo systemctl start dns-g
sudo systemctl status dns-g
sudo journalctl -u dns-g -f

# Альтернативно через launchctl (macOS)
sudo launchctl load /Library/LaunchDaemons/com.astracat.dns-g.plist
sudo launchctl list | grep dns-g
```

## Конфигурация

Основной конфигурационный файл: `/etc/dns-g/dns-g.conf`

```bash
# Порт для прослушивания
PORT=5454

# TTL кэша в минутах
CACHE_TTL=5

# Уровень логирования
LOG_LEVEL=INFO

# Путь к файлу логов
LOG_FILE=/var/log/dns-g/dns-g.log

# Максимальное количество записей в кэше
MAX_CACHE_ENTRIES=10000

# Таймаут DNS резолвера в секундах
RESOLVER_TIMEOUT=10
```

## Тестирование

```bash
# Тест A записи
dig @localhost -p 5454 google.com A

# Тест AAAA записи  
dig @localhost -p 5454 ipv6.google.com AAAA

# Тест MX записи
dig @localhost -p 5454 gmail.com MX

# Автоматическое тестирование
dns-g-ctl test
```

## Использование в качестве DNS сервера

### Локальное использование

Добавьте `127.0.0.1` в настройки DNS вашей системы:

**Linux:**
```bash
# Временно
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

# Постоянно (Ubuntu/Debian)
sudo systemctl disable systemd-resolved
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

**macOS:**
```bash
# Системные настройки > Сеть > DNS серверы
# Добавить: 127.0.0.1
```

### Сетевое использование

Для использования DNS-g другими устройствами в сети:

1. Убедитесь что файрвол разрешает подключения на порт 5454/UDP
2. Измените настройки DNS клиентов на IP адрес сервера с DNS-g

## Производительность

- **Первый запрос**: ~300-900ms (время разрешения через интернет)
- **Кэшированный запрос**: ~40-100µs (в тысячи раз быстрее!)
- **Пропускная способность**: До 10,000 запросов/сек на современном оборудовании

## Безопасность

Установщик автоматически настраивает:

- Запуск от непривилегированного пользователя `dns-g`
- Ограничение доступа к файловой системе
- Минимальные привилегии процесса
- Изоляция временных файлов

## Устранение неполадок

### DNS-g не запускается

```bash
# Проверка статуса
dns-g-ctl status

# Просмотр логов
dns-g-ctl logs

# Проверка конфигурации
sudo -u dns-g /opt/dns-g/dns_resolver
```

### Порт уже занят

```bash
# Найти процесс использующий порт 5454
sudo lsof -i :5454
sudo netstat -tulpn | grep :5454

# Изменить порт в конфигурации
sudo nano /etc/dns-g/dns-g.conf
```

### Проблемы с разрешением DNS

```bash
# Тест подключения к интернету
ping 8.8.8.8

# Проверка DNS серверов системы
cat /etc/resolv.conf

# Тест вручную
dig @8.8.8.8 google.com A
```

## Удаление

```bash
# Полное удаление DNS-g
sudo ./install.sh --uninstall
```

Это удалит:
- Все файлы DNS-g
- Системный сервис  
- Пользователя dns-g
- Конфигурационные файлы
- Логи

## Поддержка

- **GitHub**: https://github.com/ASTRACAT2022/dns-g
- **Issues**: https://github.com/ASTRACAT2022/dns-g/issues
- **Документация**: https://github.com/ASTRACAT2022/dns-g/blob/main/README.md

## Лицензия

MIT License - см. файл LICENSE в репозитории.
