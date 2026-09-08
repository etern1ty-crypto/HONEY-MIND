# Архитектура и внутренние контракты

## Компоненты

| Модуль                    | Ответственность                                                        |
| ------------------------- | ---------------------------------------------------------------------- |
| `src/main.rs`             | CLI, запуск runtime, контроль writer/server, сигналы, exit status      |
| `src/config.rs`           | TOML, defaults, семантические границы, нормализация IP, проверка binds |
| `src/server.rs`           | Предварительное связывание сокетов, admission, supervision и shutdown  |
| `src/protocols/mod.rs`    | Единая точка чтения/записи с deadline и input budget                   |
| `src/protocols/http.rs`   | Ограниченная обработка HTTP headers и один ответ                       |
| `src/protocols/ssh.rs`    | Identification-строки SSH, без transport/auth                          |
| `src/protocols/telnet.rs` | Потоковый IAC decoder, строки NVT и отказ в логине                     |
| `src/protocols/raw.rs`    | Необязательный banner и ограниченный приём bytes                       |
| `src/session.rs`          | Event model, минимизация данных и JSONL schema v2                      |
| `src/ratelimit.rs`        | Точное sliding window, ограниченная таблица IP                         |
| `src/logger.rs`           | Drop-newest queue, private file, OS-lock, rotation, I/O failures       |
| `src/metrics.rs`          | Registry, bounded management connections, readiness/liveness           |

## Жизненный цикл

```mermaid
sequenceDiagram
    participant CLI
    participant Bound as BoundServer
    participant Net as Listeners / Sessions
    participant Log as Writer
    CLI->>Bound: validate + bind all sockets
    Note over Bound: при ошибке sockets drop; workers ещё не запущены
    CLI->>Log: открыть и заблокировать log sink
    CLI->>Net: запустить отслеживаемые задачи
    Net->>Net: установить readiness
    Net->>Log: ограниченные session records
    CLI->>Net: CancellationToken
    Net->>Log: финальные shutdown records
    Net-->>CLI: все дочерние задачи завершены
    CLI->>Log: удалить последних producers
    Log-->>CLI: очередь drained и записи flushed
```

`BoundServer::bind` возвращает реальные адреса портов `0`, поэтому integration tests
не используют небезопасную схему «занять порт → освободить → надеяться занять снова».
На этапе bind ОС уже может принимать TCP handshake в backlog, но обработчики
сессий не запускаются, пока не подготовлены все endpoints и management listener.

`BoundServer::run` владеет JoinSet workers. Каждый listener владеет своим JoinSet
сессий. Management-сервер владеет отдельным JoinSet. Отсоединённых fire-and-forget
сетевых задач нет. Panic/accept error отменяет общий token и возвращает ошибку.

CLI ограничивает runtime числом до 8 async worker threads и до 8 blocking threads.
Это не позволяет числу ядер хоста автоматически нарушить process/task budget.

## Admission и пределы

Порядок: exact-IP exclusion → per-IP limiter → global semaphore → protocol task.
Решение IP limiter потребляет слот окна до попытки взять global permit, поэтому
частые подключения при глобальном насыщении тоже могут быть ограничены по IP.
IPv4-mapped IPv6 приводится к IPv4 для exclusions и rate-limit buckets.

- Sliding window хранит только допущенные к следующему admission-шагу timestamps за последние 60 секунд.
- При заполненной таблице новые IP отклоняются до очистки; старые активные IP не вытесняются.
- Очистка раз в секунду. Истёкшая запись находится вне окна уже на границе ровно 60 секунд.
- При poisoned mutex admission закрывается с причиной `rate_limiter_unavailable`.
- Сессия имеет I/O deadline и независимый абсолютный lifetime; slow trickle не продлевает lifetime.
- Чтение ограничено `max_read_bytes_per_session`, preview — отдельным меньшим лимитом.
- HTTP headers не превышают 8192 bytes и 64 полей; Telnet хранит не более 256 decoded bytes строки.
- Telnet raw remainder ограничен буфером чтения, decoder хранит состояние между пакетами.
- В session record не более 16 events. Метрики не получают IP, URI, usernames или произвольные tags как labels.

Это application-level ограничения. Они не ограничивают SYN backlog, нагрузку
сетевого стека, bandwidth или CPU всех процессов хоста. Необходимы firewall,
OS/cgroup limits и наблюдение за узлом.

## Политика данных

Минимизация применяется в `SessionState::push_event` **до** помещения события в
состояние и очередь. При metadata-mode raw preview вообще не накапливается.
Parsed credentials временно существуют в памяти protocol handler; zeroization
памяти и DLP не реализованы. URL path и SSH identification также могут содержать
чувствительные строки, придуманные клиентом. См. [конфигурацию](CONFIGURATION.md).

`bytes_received` означает байты, реально прочитанные приложением, а не pcap-volume.
После достижения общего лимита следующие байты не читаются и не считаются.
При завершении среди непрочитанных входящих данных клиент может увидеть TCP reset.

## Очередь и хранение

Producer использует `try_send`: переполненная очередь отбрасывает **новую** запись.
Существующие записи сохраняют порядок. Счётчик потери увеличивается; backpressure
не переносится на сетевые сессии. Это не durable queue и не exactly-once доставка.

Writer сериализует полную JSONL-строку, пишет во все выбранные sinks, flush-ит
и только затем увеличивает `logger_written_total`. Если один sink успешен,
а другой отказал, запись может остаться в первом; повторной отправки нет.
`flush` не равен `fsync`: durability при потере питания не гарантируется.

Размер текущего файла ограничен `max_file_bytes`, число архивов — `max_files`.
Ротация: удалить самый старый архив, сдвинуть остальные, переименовать текущий в `.1`,
открыть новый. Rename-цепочка не является транзакцией на случай crash;
для долгого хранения используйте внешний collector. При незавершённой последней
строке на старте процесс отказывается тихо продолжать повреждённый JSONL.

Lock хранится в соседнем `.lock`; освобождается ОС при закрытии descriptor или
завершении процесса. **Не удаляйте lock-файл работающего сенсора.**
Unix `O_NOFOLLOW`, проверка regular files и права `0600` уменьшают риск ссылок/утечек,
но родительский каталог также должен быть приватным. Это не защита от root или
владельца каталога, одновременно заменяющего файлы.

## Отказы и остановка

Fatal writer error снижает readiness, увеличивает error counter и завершает writer.
CLI замечает результат, отменяет сетевые задачи, дренирует доступные записи и
возвращает ненулевой exit code. Внешний алерт `up == 0` обязателен: процесс может
завершиться раньше следующего scrape и локальный error counter не будет прочитан.

Grace применяется отдельно к server и logger. После deadline task abort-ится;
неоконченные записи могут потеряться, exit code ненулевой. При стандартных настройках
верхний процессный бюджет — два grace-периода плюс 2 секунды runtime shutdown,
без обещания real-time guarantees для планировщика/ядра.
Tokio blocking I/O нельзя надёжно отменить на уровне ОС; ограниченный teardown
runtime не ждёт зависшую блокирующую операцию бесконечно.
