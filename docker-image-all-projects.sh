#!/bin/sh
set -e

command -v docker compose >/dev/null 2>&1 || { echo "Docker Compose не установлен. Установите его и повторите попытку." >&2; exit 1; }

echo "Начинаем сборку всех Docker-образов через Docker Compose..."

docker compose build || { echo "Ошибка при сборке контейнеров"; exit 1; }
docker compose up -d || { echo "Ошибка при запуске контейнеров"; exit 1; }

echo "Сервисы успешно запущены!"
