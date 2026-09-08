# CLI, management HTTP и JSONL

## CLI

```text
minotaur [--config PATH] [COMMAND]
```

| Command                                                 | Действие                                         |
| ------------------------------------------------------- | ------------------------------------------------ |
| `run`                                                   | Запустить sensor; default при отсутствии команды |
| `validate-config [--json]`                              | TOML и semantic validation без bind/open log     |
| `print-config [--profile local                          | sensor]`                                         | Полный config в stdout; существующий config не читается |
| `healthcheck [--address IP:PORT] [--timeout-seconds 3]` | GET `/readyz`; deadline 1–30 секунд              |
| `--help`, `--version`                                   | Справка и версия                                 |

Глобальный `--config/-c` можно указывать до или после подкоманды.
Путь также берётся из `MINOTAUR_CONFIG`. Диагностика — stderr, JSONL — выбранные sinks.
Config printing использует stdout: перенаправление `>` перезапишет целевой файл,
поэтому не направляйте его в конфигурацию работающего сенсора без копии.

Примеры:

```bash
minotaur print-config --profile sensor > sensor.toml
minotaur validate-config -c sensor.toml --json
MINOTAUR_CONFIG=sensor.toml RUST_LOG=minotaur=debug minotaur run
minotaur healthcheck --address 127.0.0.1:9090 --timeout-seconds 2
```

Коды: `0` — успех; `1` — runtime/config/bind/writer/health failure;
`2` обычно используется Clap для неверных аргументов. SIGINT/SIGTERM при
успешном drain дают `0`, fatal error или forced abort — `1`.
`validate-config` не проверяет свободность порта или доступность log directory.

## Management HTTP

| Route       | Method | Результат                                                 |
| ----------- | ------ | --------------------------------------------------------- |
| `/healthz`  | GET    | 200, если management handler отвечает; liveness           |
| `/readyz`   | GET    | 200 при readiness=1 и отсутствии writer errors; иначе 503 |
| `/metrics`  | GET    | Prometheus text exposition 0.0.4; ошибки rendering → 500  |
| Другой path | GET    | 404                                                       |
| Любой path  | Не GET | 405 и `Allow: GET`                                        |

Ни TLS, ни authentication не встроены. Keep-alive выключен; cache запрещён.
Timeout относится к соединению целиком, а не только к одному header read.
Healthcheck на wildcard bind автоматически подключается к соответствующему loopback.
`--address` позволяет проверить management без чтения TOML.

## Метрики

Все метрики имеют постоянные labels `sensor_id` и `environment`.
`protocol` — только raw/ssh/http/telnet. Sensor tags, IP, path и username не являются labels.

| Имя                                   | Тип / дополнительные labels | Обновление                               |
| ------------------------------------- | --------------------------- | ---------------------------------------- |
| `minotaur_connections_total`          | counter / protocol          | При admission сессии                     |
| `minotaur_rejected_total`             | counter / protocol, reason  | При отказе admission                     |
| `minotaur_active_sessions`            | gauge                       | RAII lifetime сессии                     |
| `minotaur_bytes_received_total`       | counter / protocol          | При закрытии сессии                      |
| `minotaur_session_duration_seconds`   | histogram / protocol        | При закрытии                             |
| `minotaur_closed_sessions_total`      | counter / protocol, reason  | При закрытии                             |
| `minotaur_events_total`               | counter / protocol, event   | Parsed events при закрытии               |
| `minotaur_logger_written_total`       | counter                     | После flush всех выбранных sinks         |
| `minotaur_logger_dropped_total`       | counter / reason            | queue_full, channel_closed, writer_error |
| `minotaur_logger_errors_total`        | counter                     | Fatal writer failure                     |
| `minotaur_tracked_ips`                | gauge                       | Раз в секунду                            |
| `minotaur_ready`                      | gauge                       | 0/1                                      |
| `minotaur_metrics_active_connections` | gauge                       | RAII management connection               |
| `minotaur_metrics_rejected_total`     | counter                     | Management admission at capacity         |

Admission reasons: `ignored_ip`, `rate_limit`, `rate_limit_capacity`,
`rate_limiter_unavailable`, `max_sessions`.
Connection counters включают TCP-проверки и сканеры, не только атаки.
Метрики сбрасываются при restart; это не долговременный audit log.

## JSONL schema v2

Полный [machine-readable schema](session.schema.json) и
[синтетический пример](../examples/session.metadata.json).
Одна строка — итог **одной admitted TCP-сессии**, а не одного packet/request.
Rejected connections представлены counters, не отдельными JSONL-строками.

| Группа               | Поля                                                               |
| -------------------- | ------------------------------------------------------------------ |
| Версия/идентификация | `schema_version=2`, `session_id`, `sensor`, `endpoint`, `protocol` |
| Сеть/время           | `ts` UTC на старте, `src`, `dst`, `dst_port`, `duration_ms`        |
| Объём                | `bytes_received`, `payload_captured`, `bytes_truncated`            |
| Данные               | `data_preview_hex`, `data_preview_ascii`, `privacy_mode`           |
| События              | `events`, `events_truncated`, `close_reason`                       |

`data_preview_*` остаются пустыми при metadata; это не zero-byte connection.
`bytes_truncated` отражает именно ограничение **включённого** preview, а не privacy suppression.
`dst` берётся из connected socket, поэтому wildcard bind не теряет конкретный destination IP.

Event types:

- `ssh_client_banner`: `banner`, после проверки identification.
- `http_request`: `method`, `path`, `version`, nullable `host`, `user_agent`.
- `telnet_login`: `username`, nullable `password`, `credentials_redacted`.
- `notice`: статический `msg`, например `http_headers_too_large` или `telnet_line_too_long`.

Close reasons: `client_closed`, `timeout`, `lifetime_limit`, `byte_limit`,
`protocol_error`, `server_closed`, `error`, `shutdown`.
Idle timeout и абсолютный lifetime различаются, чтобы разбирать slow-trickle сессии.

## Правила для потребителя событий

1. Разбирайте JSON, а не конкатенируйте строки в shell/SQL/HTML.
2. Считайте client-controlled values недоверенными; escape при отображении.
3. Используйте session_id для дедупликации downstream. Exactly-once не обещается.
4. Проверяйте schema_version и privacy_mode, не интерпретируйте `[redacted]` как реальный пароль.
5. Отслеживайте log drops и `up`; не выводите «атак нет» из пустого файла при отказе collector.

Schema не заявлена как ECS/OCSF-совместимая. При необходимости преобразуйте её
в контракт вашей SIEM в управляемом collector с отдельными тестами mapping.
