# Mini OAuth2

Два приложения: Auth выдаёт и отзывает токены, Resource Server проверяет доступ к платежам.

## Структура

- `oauth-common` — HS256, JSON-токены, проверка времени через `Clock`, общие ошибки и логи.
- `auth-server` — контроллеры, DTO, сервис авторизации, JPA-сущности и репозитории.
- `resource-server` — контроллер платежей, DTO, фильтр Bearer и HTTP-клиент интроспекции.

Auth хранит пользователей, клиентов, роли, refresh-токены и отзывы в БД.
RS проверяет подпись локально, затем вызывает `/introspect` для проверки отзыва и актуальных прав.

## Запуск

Команды выполняются **из корня проекта**. Нужны Java 17+ и Maven.

```bash
./mvnw clean verify
```

Первый запуск Auth **с пустой БД** и учебными данными:

```bash
java -jar auth-server/target/auth-server-1.0-SNAPSHOT.jar \
  --spring.sql.init.data-locations=file:./auth-server/src/test/resources/fixtures/auth-data.sql
```

При последующих запусках параметр заполнения **не передавать**:

```bash
java -jar auth-server/target/auth-server-1.0-SNAPSHOT.jar
```

В другом терминале запустить RS:

```bash
java -jar resource-server/target/resource-server-1.0-SNAPSHOT.jar
```

Auth доступен на `http://localhost:8080`, RS — на `http://localhost:9090`.
Без параметра заполнения создаются только таблицы.

Учебные учётные записи из SQL-файла:

| Учётная запись | Пароль / secret | Права |
| --- | --- | --- |
| Пользователь `alice` | `pass` | `viewer`: `payments:read` |
| Пользователь `bob` | `pass` | `operator`: чтение и запись |
| Пользователь `blocked` | `pass` | Заблокирован |
| Клиент `cli-001` | `secret` | password, refresh_token, client_credentials; чтение и запись |
| Клиент `service-001` | `secret` | Только client_credentials; чтение |

В БД пароли и секреты представлены BCrypt-хешами.
Тесты используют этот SQL независимо от обычного запуска и не изменяют рабочую БД.

## API

| Метод | Путь | Назначение |
| --- | --- | --- |
| POST | `/token` | `password`: access + refresh; `client_credentials`: только access |
| POST | `/token/refresh` | Обмен refresh на новую пару; старый становится использованным |
| POST | `/revoke` | Отзыв access или refresh; успешный ответ `200` без тела |
| POST | `/introspect` | Проверка access: `active:true` с claims либо `active:false` |
| GET | `/api/payments` | Требуется `payments:read` |
| POST | `/api/payments` | Требуется `payments:write`; создание платежа имитируется |

Примеры ниже используют `jq` только для извлечения токенов из JSON:

```bash
PAIR=$(curl -sS http://localhost:8080/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"password","username":"alice","password":"pass","client_id":"cli-001","client_secret":"secret","scopes":["payments:read"]}')
ACCESS=$(printf '%s' "$PAIR" | jq -r '.access_token')
REFRESH=$(printf '%s' "$PAIR" | jq -r '.refresh_token')

curl -i http://localhost:9090/api/payments -H "Authorization: Bearer $ACCESS"

curl -sS http://localhost:8080/introspect \
  -H 'Content-Type: application/json' -d "{\"token\":\"$ACCESS\"}"

curl -sS http://localhost:8080/token/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"grant_type\":\"refresh_token\",\"refresh_token\":\"$REFRESH\",\"client_id\":\"cli-001\",\"client_secret\":\"secret\"}"

curl -i http://localhost:8080/revoke \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ACCESS\",\"token_type_hint\":\"access_token\"}"

curl -sS http://localhost:8080/token \
  -H 'Content-Type: application/json' \
  -d '{"grant_type":"client_credentials","client_id":"service-001","client_secret":"secret"}'
```

Для записи получите токен пользователя `bob` со scope `payments:write`:

```bash
curl -i http://localhost:9090/api/payments \
  -H 'Authorization: Bearer <access_bob>' -H 'Content-Type: application/json' \
  -d '{"amount":100,"currency":"RUB"}'
```

`token_type_hint` необязателен: фактический тип определяется по подписанному токену.
В `/token/refresh` поле `grant_type` можно опустить, `scopes` передавать нельзя.
Сервер сохраняет исходные права refresh, исключая права, которых больше нет у пользователя или клиента.

## Конфигурация и БД

Настройки находятся в `application.properties` каждого приложения.
Основные переменные окружения:

| Переменная | По умолчанию |
| --- | --- |
| `AUTH_SECRET` | Учебный ключ из properties; одинаковый у Auth и RS|
| `AUTH_ISSUER` | `mini-auth` |
| `ACCESS_TTL_SEC` / `REFRESH_TTL_DAYS` | `900` / `14` |
| `CLOCK_SKEW` | `30` секунд |
| `AUTH_URL` | `http://localhost:8080` для RS |
| `RS_AUDIENCE` | `payments-api`; должна совпадать с audience клиента в БД |
| `AUTH_DB_URL` | `jdbc:h2:file:./data/auth;DB_CLOSE_ON_EXIT=FALSE` |
| `AUTH_DB_USER` / `AUTH_DB_PASSWORD` | `user` / `password` для H2 |

Схема: [init.sql](auth-server/src/main/resources/init.sql). 
Файловая H2 сохраняет сессии после перезапуска; секрет должен оставаться тем же.

Для PostgreSQL создайте БД, задайте `AUTH_DB_URL`, `AUTH_DB_USER`, `AUTH_DB_PASSWORD`
и запустите Auth с `--spring.profiles.active=postgres`. Автотесты выполняются на H2.

## Токены, ошибки и ограничения

Формат — `header.payload.signature`, подпись HS256; Base64URL не шифрует данные.
Refresh реализован по варианту B: подписанный JSON с `typ=RT` и `refresh_id`, плюс запись в БД.
Проверяются issuer, audience, тип, iat/exp, идентификатор, отзыв, роли и scopes.
Отзыв access действует на следующем запросе RS; кэша интроспекции нет.

Ошибки имеют поля `error` и `error_description`: `400` — параметры,
`401` — credentials/токен, `403` — права/блокировка, `409` — повторный refresh,
`503` — недоступна интроспекция, `500` — внутренний сбой.
Логи пишутся в консоль и `logs/auth-server.log`, `logs/resource-server.log`, без паролей и токенов.
