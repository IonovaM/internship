# Сервис профиля пользователя

В этом сервисе находится публичный профиль пользователя и вся связанная с этим информация.

## Сущности

```mermaid
classDiagram

class Profile {
  +user_id: int @primary @foreign
  +firstname: string
  +lastname: string
  +birthday?: Date
  +bio?: string
}
```

Реальное имя пока сделаем необязательным.
То же самое касается дня рождения и биографии.