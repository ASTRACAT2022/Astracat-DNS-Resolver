# DNS Resolver

Полноценный DNS resolver, использующий библиотеку [dnsr](https://github.com/domainr/dnsr), созданный как аналог PowerDNS с высокой производительностью и кэшированием.

## Особенности

- **Высокая производительность**: Обработка запросов за микросекунды благодаря эффективному кэшированию
- **Многоуровневое кэширование**: 
  - Внутренний кэш dnsr библиотеки (10,000 записей)
  - Кэш приложения с TTL 5 минут
- **Поддержка всех основных типов записей**: A, AAAA, CNAME, MX, NS, TXT
- **Конкурентная обработка**: Каждый запрос обрабатывается в отдельной горутине
- **Автоматическое повторение по TCP**: При усечении UDP пакетов
- **Детальное логирование**: Время обработки, статистика кэша, ошибки

## Требования

- Go 1.25.0+
- Доступ к интернету для разрешения DNS запросов

## Установка и запуск

### Автоматическая установка (рекомендуется)

```bash
# Быстрая установка с автоматической настройкой сервиса
curl -sSL https://raw.githubusercontent.com/ASTRACAT2022/dns-g/main/install.sh | sudo bash

# Или клонировать и запустить локально
git clone https://github.com/ASTRACAT2022/dns-g.git
cd dns-g
sudo ./install.sh
```

Автоматический установщик:
- ✅ Устанавливает все зависимости (включая Go)
- ✅ Создает системный сервис (systemd/launchd)
- ✅ Настраивает автозапуск
- ✅ Конфигурирует файрвол
- ✅ Создает команды управления

После установки используйте:
```bash
dns-g-ctl start     # Запуск сервиса
dns-g-ctl status    # Проверка статуса
dns-g-ctl test      # Тестирование DNS
```

### Ручная установка

```bash
# Клонирование репозитория
git clone https://github.com/ASTRACAT2022/dns-g.git
cd dns-g

# Установка зависимостей
go mod tidy

# Сборка
go build -o dns_resolver main.go

# Запуск
./dns_resolver
```

Сервер запустится на порту **5454** (изменен с 5353 для избежания конфликта с системным mDNS).

## Использование

### Тестирование с помощью dig

```bash
# A записи
dig @localhost -p 5454 google.com A +short

# AAAA записи
dig @localhost -p 5454 ipv6.google.com AAAA +short

# MX записи
dig @localhost -p 5454 gmail.com MX +short

# TXT записи
dig @localhost -p 5454 example.com TXT +short

# CNAME записи
dig @localhost -p 5454 www.example.com CNAME +short
```

### Автоматическое тестирование

Запустите тестовый скрипт для комплексной проверки:

```bash
./test_dns_resolver.sh
```

### Юнит-тесты

```bash
go test -v
```

## Производительность

Результаты тестирования показывают отличную производительность:

- **Первый запрос**: ~300-900ms (время разрешения через интернет)
- **Кэшированный запрос**: ~40-100µs (в тысячи раз быстрее!)

### Пример результатов тестирования

```
Testing example.com A record...
  example.com A - First query: OK (Time: .910319000 seconds)
  example.com A - Second query: OK (Time: .007494000 seconds)

Testing ipv6.google.com AAAA record...
  ipv6.google.com AAAA - First query: OK (Time: .730056000 seconds)
  ipv6.google.com AAAA - Second query: OK (Time: .008414000 seconds)
```

## Архитектура

### Основные компоненты

1. **UDP Сервер**: Слушает на порту 5454, обрабатывает DNS запросы
2. **dnsr.Resolver**: Библиотека для разрешения DNS запросов с собственным кэшем
3. **Кэш приложения**: Дополнительный уровень кэширования с настраиваемым TTL
4. **Конкурентная обработка**: Каждый запрос обрабатывается в отдельной горутине

### Конфигурация

```go
const (
    listenPort = 5454               // Порт для прослушивания
    cacheTTL   = 5 * time.Minute    // TTL кэша приложения
)

// Настройки dnsr.Resolver
resolver = dnsr.NewResolver(
    dnsr.WithCache(10000),            // Кэш на 10000 записей
    dnsr.WithTimeout(10*time.Second), // Таймаут 10 секунд
    dnsr.WithExpiry(),                // Очистка устаревших записей
    dnsr.WithTCPRetry(),              // Повтор по TCP при усечении
)
```

## Поддерживаемые типы записей

| Тип | Описание | Поддержка |
|-----|----------|-----------|
| A | IPv4 адреса | ✅ |
| AAAA | IPv6 адреса | ✅ |
| CNAME | Канонические имена | ✅ |
| MX | Mail exchange | ✅ |
| NS | Name servers | ✅ |
| TXT | Текстовые записи | ✅ |
| SOA | Start of authority | ⏭️ (пропускается) |

## Мониторинг

Сервер предоставляет детальное логирование:

- Время обработки каждого запроса
- Статистика попаданий/промахов кэша
- Ошибки разрешения DNS
- Информация о клиентах

### Пример логов

```
2025/08/21 13:36:16 Cache miss for example.com._1 from [::1]:50366
2025/08/21 13:36:17 Resolved example.com. A: 8 records
2025/08/21 13:36:17 Request from [::1]:50366 processed in 891.967167ms
2025/08/21 13:36:17 Cache hit for example.com._1 from [::1]:51216
2025/08/21 13:36:17 Request from [::1]:51216 processed in 65.25µs
```

## Файлы проекта

- `main.go` - Основной код DNS сервера
- `main_test.go` - Юнит-тесты
- `test_dns_resolver.sh` - Скрипт для интеграционного тестирования
- `go.mod` / `go.sum` - Управление зависимостями Go
- `README.md` - Документация

## Зависимости

- [github.com/domainr/dnsr](https://github.com/domainr/dnsr) - DNS resolver библиотека
- [github.com/miekg/dns](https://github.com/miekg/dns) - DNS протокол для Go

## Лицензия

Проект распространяется под лицензией MIT.

## Автор

Создано как высокопроизводительная альтернатива PowerDNS с использованием современных технологий Go.
