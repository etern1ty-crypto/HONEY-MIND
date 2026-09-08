# Настройка

## Загрузка и приоритет

```bash
minotaur print-config --profile local > minotaur.toml
minotaur -c minotaur.toml validate-config --json
```

Приоритет пути: `--config/-c` → `MINOTAUR_CONFIG` → `minotaur.toml`.
TOML — единственный источник рабочих параметров. `.env` автоматически не читается,
подстановки `${VARIABLE}` в TOML нет. `RUST_LOG` управляет диагностикой на stderr.
Все неизвестные поля отвергаются. Максимальный конфиг — 64 KiB; требуется хотя бы один endpoint.

**Относительный `logging.output` разрешается относительно каталога TOML-файла**, а не CWD.
Родительские каталоги автоматически не создаются. Профиль systemd использует абсолютный путь.

## Sensor и privacy

| Поле                        | Default        | Ограничение / смысл                                                        |
| --------------------------- | -------------- | -------------------------------------------------------------------------- |
| `sensor.id`                 | `local-sensor` | Уникальный id установки; 1–64 ASCII letters/digits/`._-`                   |
| `sensor.environment`        | `development`  | Те же ограничения; alert приманки по умолчанию фильтрует `production`      |
| `sensor.tags`               | `{}`           | До 8 пар; ключ как id, value до 128 UTF-8 bytes без controls; только JSONL |
| `privacy.mode`              | `metadata`     | `metadata` или `full`                                                      |
| `privacy.capture_http_path` | `true`         | Сохранять structured path; `false` заменяет его на `[redacted]`            |

### Матрица минимизации

| Данные                                             | metadata                                             | full                                           |
| -------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------------- |
| Source/destination IP, port, UUID, время, counters | Сохраняются                                          | Сохраняются                                    |
| SSH client identification                          | Сохраняется                                          | Сохраняется                                    |
| HTTP method/version                                | Сохраняются                                          | Сохраняются                                    |
| HTTP path                                          | По `capture_http_path`, без query/fragment           | По `capture_http_path`, включая query/fragment |
| HTTP Host/User-Agent                               | `null`                                               | Сохраняются в пределах parser limits           |
| Telnet username/password                           | `[redacted]`; отсутствующий password остаётся `null` | Сохраняются; пустой введённый password — `""`  |
| Raw preview                                        | Не накапливается                                     | Первые N bytes по preview cap                  |

В `full` сырой preview может содержать Authorization, Cookie и все прочие секреты
независимо от `capture_http_path`. Специального поля Authorization в event нет,
но это не означает его удаления из raw bytes. Используйте `full` только на
согласованном изолированном исследовательском стенде с определёнными правами доступа.
Metadata — минимизация, **не гарантия анонимности**: IP, path и SSH banner могут
содержать персональные данные. Для более строгого режима отключите capture_http_path.

## Logging

| Поле                            | Default          | Допустимые значения                                        |
| ------------------------------- | ---------------- | ---------------------------------------------------------- |
| `logging.output`                | `honeypot.jsonl` | Путь, `"-"` или `""`; последние два всегда означают stdout |
| `logging.stdout`                | `false`          | При файловом output также зеркалить JSONL на stdout        |
| `logging.buffer_size`           | `256`            | 1–4096 records, drop-newest при заполнении                 |
| `logging.max_file_bytes`        | `10485760`       | 1 MiB–1 GiB на активный файл                               |
| `logging.max_files`             | `3`              | 1–20 архивов, **плюс** текущий файл                        |
| `logging.write_timeout_seconds` | `3`              | 1–30 секунд на opening sink / запись во все sinks          |

Максимум новых файловых данных при default retention — около 40 MiB плюс небольшой
lock-файл. Это не квота для заранее существовавших больших файлов и не лимит stdout.
Для stdout retention задаётся collector/container logging driver.

Для оценки очереди validation использует консервативный бюджет
`buffer_size × (65536 + 3 × max_bytes_per_session) <= 256 MiB`.
Это validation guard, не измерение реального RSS. Коэффициент учитывает hex/ASCII,
но реальная сериализация и allocator имеют накладные расходы.

При ошибке файла/pipe процесс останавливается, вместо молчаливого продолжения без лога.
Старые записи не удаляются вне ротации; учтите права и retention экспортирующего collector.

## Server

| Поле                           | Default | Граница                                                    |
| ------------------------------ | ------- | ---------------------------------------------------------- |
| `max_concurrent_sessions`      | `256`   | 1–4096, общая для всех приманок                            |
| `session_timeout_seconds`      | `15`    | 1–300, каждый read/write                                   |
| `max_session_duration_seconds` | `60`    | 1–3600, абсолютная длительность                            |
| `shutdown_grace_seconds`       | `10`    | 1–60, отдельно server drain и writer drain                 |
| `rate_limit_per_ip_per_min`    | `30`    | 0–10000, `0` выключает limiter                             |
| `max_tracked_ips`              | `4096`  | 1–65536; новые IP отклоняются при заполнении               |
| `max_bytes_per_session`        | `1024`  | 0–65536, только preview; `0` выключает preview даже в full |
| `max_read_bytes_per_session`   | `65536` | 1–16777216, общий input budget                             |
| `ignore_source_ips`            | `[]`    | До 256 точных IP, не CIDR; соединение сразу закрывается    |

Все поля в таблице находятся в `[server]`.
Preview не может превышать read budget. История limiter дополнительно ограничена:
`max_tracked_ips × rate_limit_per_ip_per_min <= 1_000_000 timestamps`.
Игнорируемые IP сравниваются после нормализации IPv4-mapped IPv6; повторения запрещены.
Игнорирование адреса создаёт blind spot, поэтому не исключайте большие monitoring/NAT группы автоматически.

## Metrics

| Поле                              | Default          | Граница                                                    |
| --------------------------------- | ---------------- | ---------------------------------------------------------- |
| `metrics.enabled`                 | `false`          | В bundled profiles явно включён                            |
| `metrics.bind`                    | `127.0.0.1:9090` | Числовой socket address, не DNS имя                        |
| `metrics.allow_remote`            | `false`          | Явно требуется для non-loopback bind; не включает auth/TLS |
| `metrics.max_connections`         | `16`             | 1–256                                                      |
| `metrics.request_timeout_seconds` | `3`              | 1–30 на соединение целиком                                 |

Management ограничен 8192-byte HTTP buffer, одним запросом на TCP-соединение
и общим deadline. Не передавайте `/metrics` через публичный reverse proxy.
Профиль контейнера слушает `0.0.0.0` внутри контейнера, но Compose публикует
management только на host loopback.

## Endpoints

От 1 до 32 блоков `[[endpoint]]`. `bind` и `protocol` обязательны.

| Поле            | Смысл                                                                                |
| --------------- | ------------------------------------------------------------------------------------ |
| `name`          | Необязательный уникальный id с тем же alphabet, что sensor.id; иначе `protocol-port` |
| `bind`          | IPv4/IPv6 SocketAddr; `127.0.0.1:2222` или `[::1]:2222`                              |
| `protocol`      | `ssh`, `http`, `telnet`, `raw`                                                       |
| `banner`        | До 4096 bytes для raw/Telnet; HTTP его не принимает                                  |
| `server_header` | Только HTTP; 1–256 printable ASCII bytes, без CR/LF; default `nginx`                 |
| `http_status`   | Только HTTP; final status 200–599, default 404                                       |
| `login_prompt`  | Только Telnet; непустой, до 128 bytes без control characters; default `login: `      |

SSH banner: printable ASCII, максимум 253 bytes до добавляемого CRLF,
начало `SSH-2.0-` или `SSH-1.99-`; default `SSH-2.0-OpenSSH_9.6`.
Raw без banner ничего не отправляет. Telnet без banner начинает с login prompt.

Совпадающие и wildcard-overlapping binds запрещены; IPv6 wildcard на том же порту
консервативно считается конфликтующим с IPv4. OS bind остаётся окончательной
проверкой доступности. Port `0` допустим для тестов; реальный port попадает в событие.
Production-профиль должен использовать фиксированные согласованные порты.

## Совместимость с 0.1

- Новые поля имеют defaults; неизвестные поля и protocol-specific misconfiguration теперь отклоняются.
- Zero timeout больше не превращается молча в 1 секунду.
- Default privacy меняется на metadata: нельзя считать отсутствие пароля ошибкой ingest.
- Structured JSONL расширен и версионирован как schema v2.
- Относительный log path теперь отсчитывается от config directory.
- Нет hot reload. Изменения вступают в силу после validation и restart.
