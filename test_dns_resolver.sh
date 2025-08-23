#!/bin/bash

# Тестирование DNS резолвера

# Проверяем, запущен ли сервер
if ! pgrep -f "dns_resolver" > /dev/null; then
  echo "Запускаем DNS резолвер..."
  go run main.go &
  sleep 2 # Даем время на запуск
fi

# Тестовые запросы
echo -e "\nТестируем A запись (google.com):"
dig @127.0.0.1 -p 5454 google.com A +short

echo -e "\nТестируем CNAME запись (www.google.com):"
dig @127.0.0.1 -p 5454 www.google.com CNAME +short

echo -e "\nТестируем MX запись (google.com):"
dig @127.0.0.1 -p 5454 google.com MX +short

# Останавливаем сервер, если был запущен нами
if [ "$1" == "--stop" ]; then
  pkill -f "dns_resolver"
  echo "Сервер остановлен"
fi
