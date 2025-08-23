#!/bin/bash

# Имя Dockerfile
DOCKERFILE_NAME="Dockerfile"

# Имя образа и контейнера
IMAGE_NAME="my-dns-server"
CONTAINER_NAME="dns-container"

# Функция для создания Dockerfile
create_dockerfile() {
    cat <<EOF > $DOCKERFILE_NAME
# Используем официальный образ Go в качестве базового.
FROM golang:1.22

# Устанавливаем рабочую директорию внутри контейнера.
WORKDIR /app

# Копируем файлы go.mod и go.sum (если они есть), чтобы скачать зависимости.
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Копируем исходный код приложения в контейнер.
COPY . .

# Собираем приложение.
# -o dns-server указывает имя исполняемого файла.
# CGO_ENABLED=0 делает исполняемый файл статически скомпилированным,
# что позволяет запускать его в минимальных образах.
RUN CGO_ENABLED=0 GOOS=linux go build -o dns-server .

# Используем легковесный базовый образ для уменьшения размера конечного образа.
FROM alpine:latest

# Устанавливаем рабочую директорию.
WORKDIR /root/

# Копируем исполняемый файл из предыдущего образа.
COPY --from=0 /app/dns-server .

# Открываем порт 5454.
EXPOSE 5454

# Запускаем приложение.
CMD ["./dns-server"]
EOF
    echo "Dockerfile успешно создан."
}

# Проверяем, существует ли Dockerfile
if [ ! -f "$DOCKERFILE_NAME" ]; then
    echo "Dockerfile не найден. Создаём новый файл..."
    create_dockerfile
else
    echo "Dockerfile уже существует. Продолжаем..."
fi

echo "Останавливаем и удаляем старый контейнер (если он есть)..."
docker stop $CONTAINER_NAME > /dev/null 2>&1
docker rm $CONTAINER_NAME > /dev/null 2>&1

echo "Собираем Docker-образ..."
docker build -t $IMAGE_NAME .

if [ $? -eq 0 ]; then
    echo "Образ успешно собран. Запускаем новый контейнер..."
    docker run -d -p 5454:5454 --name $CONTAINER_NAME $IMAGE_NAME
    if [ $? -eq 0 ]; then
        echo "Контейнер запущен!"
        echo "Проверь статус: docker ps | grep $CONTAINER_NAME"
    else
        echo "Ошибка при запуске контейнера."
        exit 1
    fi
else
    echo "Ошибка при сборке образа. Проверь Dockerfile."
    exit 1
fi
