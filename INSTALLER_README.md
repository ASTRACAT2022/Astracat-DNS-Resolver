# Установщик DNS-g

Автоматический скрипт установки для DNS сервера DNS-g от ASTRACAT.

## Быстрый старт

```bash
# Простая установка
sudo ./install.sh

# Показать справку
./install.sh --help

# Удалить DNS-g
sudo ./install.sh --uninstall
```

## Что включает установщик

- ✅ Автоматическая установка Go 1.25.0+ (если требуется)
- ✅ Создание системного пользователя `dns-g`
- ✅ Сборка и установка DNS сервера
- ✅ Настройка systemd/launchd сервиса
- ✅ Конфигурация файрвола
- ✅ Создание скриптов управления
- ✅ Автоматическое тестирование

## Поддерживаемые системы

- Ubuntu/Debian
- CentOS/RHEL/Rocky Linux
- Fedora
- macOS 10.15+

## После установки

```bash
# Управление сервисом
dns-g-ctl start|stop|restart|status|logs|test

# Тестирование
dig @localhost -p 5454 google.com A
```

## Структура установки

```
/opt/dns-g/          # Программы
/etc/dns-g/          # Конфигурация
/var/log/dns-g/      # Логи
```

Подробная документация: [INSTALL.md](INSTALL.md)
