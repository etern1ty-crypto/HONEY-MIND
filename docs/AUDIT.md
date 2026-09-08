# Аудит исходного архива и внесённые исправления

## Область и честный статус

База: предоставленный `HONEY-MIND-main.zip`, пакет `minotaur 0.1.0`.
Исходные файлы сохранены отдельно при работе; их checksum приведён в [протоколе](VERIFICATION.md).
Номера строк ниже относятся **к исходному архиву**, не к переписанным файлам.
Аудит основан на чтении всей небольшой кодовой базы и проверке доступными средствами.
Проверки Rust runtime ещё не выполнены: «исправление внесено» не равно
«поведение подтверждено успешным cargo test».

Приоритеты: **High** — потеря наблюдаемости/управляемости или resource exhaustion;
**Medium** — неверные протоколы/контракты/эксплуатационные границы;
**Low** — поддерживаемость и достоверность документации. Это локальная оценка,
не CVSS, не внешняя security certification.

## Реестр дефектов

| ID / риск  | Исходное место                                                                   | Дефект и последствия                                                                                                                 | Внесённое изменение / регрессия                                                                                      |
| ---------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| A01 High   | `src/logger.rs:35–45,93–110`                                                     | `output="-"` убирает файл, но stdout зависит только от отдельного флага; при false нет ни одного sink                                | `LoggingConfig::writes_stdout`, обязательный stdout alias; automated `drive.py --binary`                             |
| A02 High   | `src/server.rs:53–68`                                                            | Listener tasks запускаются по одному; ошибка позднего bind оставляет ранние задачи работающими                                       | `BoundServer::bind` до workers; `later_bind_failure_returns_without_starting_workers`                                |
| A03 High   | `src/main.rs:102–113`                                                            | Ошибка сервера превращается в warn, затем успешный exit; живые logger clones могут задержать выход                                   | Process supervisor сохраняет ошибку, отменяет workers и ограничивает drain; CLI bind-error test                      |
| A04 High   | `src/metrics.rs:94–134`                                                          | Unbounded `tokio::spawn` на management-соединение; нет deadline, лимита или join handles                                             | Ограниченный JoinSet, deadline целиком, keep-alive off; `management_slow_clients_are_bounded_and_expire`             |
| A05 High   | `src/protocols/http.rs:73–79`, `raw.rs:21–25`, `ssh.rs:35–43`, `telnet.rs:31–98` | Только чтения имели timeout; writes/flush частично бесконтрольны, ошибки местами игнорируются                                        | Общий `SessionIo::write/read`, абсолютный supervisor deadline, явный close reason                                    |
| A06 High   | `src/server.rs:161–169`, `src/protocols/raw.rs:28–34`                            | Есть inactivity timeout, но нет lifetime/input limit; trickle удерживает слот, preview cap не ограничивает чтение                    | Lifetime и total-read budgets; `continuous_trickle_cannot_reset_absolute_lifetime`, raw cap test                     |
| A07 High   | `src/ratelimit.rs:35–49,53–76`                                                   | Число уникальных IP в HashMap не имеет жёсткого предела; periodic eviction не ограничивает burst                                     | Hard IP capacity, общий timestamp budget, fail-closed mutex, deterministic boundary/eviction tests                   |
| A08 High   | `src/session.rs:24–33,52–55`, `src/protocols/telnet.rs:57–90`                    | Пароли и raw bytes сохраняются без privacy policy; HTTP query может содержать токены                                                 | Metadata default, redaction до event queue, explicit full opt-in; session privacy tests                              |
| A09 High   | `src/logger.rs:97–113`                                                           | Write/flush failures только логируются, пропавшие записи не отражаются в жизненном цикле                                             | Fatal writer result, readiness down, CLI fail-closed, loss counters; fault-injection остаётся release gate           |
| A10 Medium | `src/logger.rs:37–43`                                                            | Append без retention, private permissions, защиты от symlink и второго писателя                                                      | Bounded rotation, regular-file checks, Unix 0600/O_NOFOLLOW, OS-lock; rotation/permissions/lock tests                |
| A11 Medium | `src/config.rs:37–39`, `src/logger.rs:61–75`, `config.example.toml:16–18`        | Документация обещает drop-oldest/несуществующую метрику, реально drop-newest; closed channel не считается                            | Единый loss contract и exported counters; deterministic `overflow_and_closed_channel_are_counted_exactly`            |
| A12 Medium | `src/protocols/http.rs:30–50`                                                    | Буфер читается фиксированными кусками; cap может быть превышен до проверки, поздний delimiter принимается                            | Размер каждого read ограничен остатком cap; 431 + protocol_error; exact 8192-byte integration test                   |
| A13 Medium | `src/protocols/http.rs:87–119`                                                   | Слишком свободный request line, нет проверки версии, duplicate Host/framing и malformed headers                                      | Ограниченный strict parser, canonical errors, negative parser tests                                                  |
| A14 Medium | `src/config.rs:218–226`, `src/protocols/http.rs:57–80,122–145`                   | Допускается 1xx как окончательный response; неизвестный status получает 404 reason/body; HEAD/204/304 некорректны                    | Final 200–599, status-specific reason, no-body rules, HEAD representation length; response unit tests                |
| A15 Medium | `src/protocols/telnet.rs:107–168`                                                | Strip IAC после выделения строк: embedded LF в subnegotiation портит credentials; escaped IAC теряется                               | Потоковый state machine до line framing, состояние между reads; decoder unit tests                                   |
| A16 Medium | `src/protocols/telnet.rs:57–77,80–92,127–133`                                    | Oversize line превращается в credential; trim изменяет введённые значения; EOF перед password может смениться write error            | Strict decoded-line cap, NVT CRLF/CR-NUL, whitespace preservation, nullable missing password и правильный EOF        |
| A17 Medium | `src/config.rs:203–227`, `src/server.rs:163`                                     | Не проверяются нулевые таймауты, memory budgets, HTTP header CRLF, protocol-specific options, wildcard collisions                    | Bounded strict config, explicit remote management opt-in; negative config tests                                      |
| A18 Medium | `src/protocols/ssh.rs:57–71`                                                     | Произвольная первая строка записывается как SSH banner; oversize молча отключает parsing                                             | Проверка identification/prefix/length и notices; SSH parser/integration tests                                        |
| A19 Medium | `src/server.rs:83–88,130–133,159–176`                                            | Session tasks не отслеживаются, panic не гарантирует корректный active gauge и ошибочный exit                                        | Nested JoinSets, panic propagation, RAII ActiveGuard; shutdown/capacity integration tests                            |
| A20 Medium | `Cargo.toml:5,35`, `Cargo.lock`                                                  | Присутствует `protobuf 2.28.0` через default Prometheus feature; заявленный Rust 1.75 не подтверждён locked графом                   | Убран protobuf feature/узел; выбрана консервативная pinned toolchain; полный cargo audit/MSRV check ещё не выполнены |
| A21 Medium | `tests/integration.rs:27–31,76–77,93–101,238–249`, `src/logger.rs:159–175`       | Port-picking race, fixed sleeps, предположение об атомарности TCP read; drop test не проверяет drops                                 | Pre-bound port 0, bounded condition waits, persistent client buffers, точные assertions                              |
| A22 Low    | `src/session.rs:111–126`, `README.md`, `examples/e2e/drive.py`                   | Empty chunk на полном preview меняет truncation; vector contract не ограничен; README и smoke дают завышенные/непроверенные обещания | Truncation из фактического объёма, 16-event cap, executable smoke assertions, честные README и verification gates    |

## Что не найдено и что не является багом

В исходных production Rust-модулях не найдены `TODO`, `FIXME`, `todo!()` или
`unimplemented!()` с незавершённой функциональностью. `unwrap/expect` в тестах
не классифицируются автоматически как production vulnerabilities. Части `let _ =`
были реальными игнорируемыми I/O errors, а часть — некритической настройкой сокета.

Фиксированный HTTP response, отказ Telnet в логине и отсутствие SSH transport —
осмысленные ограничения low-interaction honeypot, не заглушки, которые нужно
заменить реальной аутентификацией или исполнением команд.

Реальные production tokens/private keys в прочитанных исходниках не обнаружены.
Пароли в tests/examples — тестовые строки, не доказательство скомпрометированных
учётных данных. Это ручной обзор, а не гарантия отсутствия всех возможных секретов.

## Зависимость protobuf: точная граница вывода

[RUSTSEC-2024-0437](https://rustsec.org/advisories/RUSTSEC-2024-0437.html)
описывает uncontrolled recursion при разборе untrusted protobuf; исправление указано
для версий `>=3.7.2`, а в архиве находится `2.28.0`.
Доказанного пути удалённой эксплуатации через minotaur не установлено: исходник
экспортирует text metrics, а не принимает protobuf messages. Удаление ненужной
функциональности — dependency hygiene и уменьшение поверхности, не демонстрация exploit.

В `Cargo.toml` выставлено `prometheus = { version = "0.13", default-features = false }`.
Root package graph обновлён без массового обновления crates; checksum остальных
пакетов сохранены. Проверка согласованности graph выполнена offline,
но **Cargo resolver и свежий полный advisory scan необходимы перед релизом**.

## Порядок исправления, реализованный в этой ревизии

1. Восстановить надёжную наблюдаемость и nonzero failures: A01–A04, A09, A19.
2. Ограничить ресурсы и длительность: A05–A07, A10–A12, A17.
3. Исправить протокольные края и privacy: A08, A13–A18, A22.
4. Привести тесты, конфигурации, dependency contract и документацию в соответствие: A20–A22.

Исправления внесены в исходники, но они не закрывают вопросы нагрузочной устойчивости,
всех возможных race conditions, платформенных различий и актуальных advisories.
Открытые release gates перечислены в [TESTING](TESTING.md) и [VERIFICATION](VERIFICATION.md).
