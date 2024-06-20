# Сервис аутентификации

Сервис аутентификации предназначен для управления пользователями и их аутентификации.

JWT-токены должны быть подписаны приватным ключом, который хранится только у Auth. Остальные сервисы хранят публичный ключ и используют его для проверки подписи.

## Сущности

```mermaid
classDiagram

class UserRole {
  <<Enum>>

  ADMIN
  USER
}

class User {
  +id: uuid @primary
  +login: string
  +email: string @unique
  +password: string (hashed)
  +role: UserRole
  +is_active: boolean
  +created_at: Date
}

User --> UserRole
```

Полезная нагрузка JWT-токена:

```json
{
  "uuid": 1,
  "role": "ADMIN",
  "exp": 1610000000
}
```
