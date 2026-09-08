# Проверки и критерии выпуска

## Полный локальный gate

Нужны Rust 1.93.1 + rustfmt/Clippy, Python 3.11+, linker и network/cache для crates.
Cargo-audit устанавливается отдельно. На машине со stable toolchain:

```bash
cargo +stable install cargo-audit --locked
cargo fmt --all
bash scripts/check.sh
```

`cargo fmt --all` форматирует рабочую копию; просмотрите diff перед commit.
`scripts/check.sh` затем проверяет формат, запускает Clippy с запретом warnings,
Rust tests, release build, repository contracts, реальный binary smoke и advisory scan.
Скрипт не выдаёт отсутствующий инструмент за успешную проверку: возвращает код 2 и `BLOCKED`.
Ни rustfmt, ни Clippy в среде подготовки не запускались; исправления, найденные gate,
нужно выполнить до объявления релиза.

## Слои тестов

| Слой                | Что проверяется                                                                                           |
| ------------------- | --------------------------------------------------------------------------------------------------------- |
| Config unit         | Defaults, unknown fields, zero limits, CRLF injection, status scope, bind overlap, путь относительно TOML |
| Session unit        | Privacy redaction, query/header stripping, preview boundary, event cap, JSON                              |
| Rate limiter unit   | Независимые IP, mapped IPv6, точная граница 60 секунд, capacity/eviction без sleep                        |
| HTTP unit           | Request grammar, framing conflicts, HEAD, no-body statuses, canonical reason                              |
| Telnet unit         | IAC fragmentation, escaped IAC, subnegotiation с LF                                                       |
| Logger unit         | JSONL flush, lock/restart, deterministic drops, rotation, Unix permissions, broken tail                   |
| Metrics unit        | Sensor labels, readiness vs liveness, method 405, RAII gauge                                              |
| TCP integration     | Все протоколы, total/idle limits, privacy, oversize input, admission, management limits, cancellation     |
| CLI integration     | Config printing/validation, nonzero invalid config и startup bind errors                                  |
| Python binary smoke | Four protocols, stdout alias, metadata contract, assigned ports, SIGTERM with live session                |

Unit/integration tests добавлены и доступны в полном исходном коде. Их наличие
не означает успешный прогон. Точный статус текущей поставки — [VERIFICATION](VERIFICATION.md).

## Почему integration harness устроен так

- Listener реально связывается с port 0 и передаётся в runtime, а не освобождается между выбором и использованием.
- Готовность/записи ожидаются по наблюдаемому условию под deadline, не через «sleep и надеемся».
- Client сохраняет unread remainder; один TCP read не обязан соответствовать одному server write.
- При panics harness отменяет/abort-ит задачи, временные ресурсы освобождаются.
- Все network operations тестов ограничены временем; SIGTERM subprocess принудительно убирается при провале.

## Offline contracts

```bash
python3 scripts/check_repository.py
```

Проверяется TOML, согласованность root lock graph, ссылки и include_str targets,
отсутствие заглушек в Rust, Python AST, обязательные файлы и синтетический JSON example.
Это **не Rust parser, не compiler, не borrow checker и не security scanner**.
При доступности дополнительных validators используется отдельная проверка JSON Schema/YAML.

## Дополнительные обязательные проверки перед публичной эксплуатацией

1. `cargo metadata --locked`, сборка и тесты на pinned и текущей stable toolchain.
2. Disk-full/permissions loss, blocked stdout, forced writer failure, partial rotation crash,
   повторный запуск и наблюдаемый nonzero exit. Проверить, что внешний мониторинг заметил отказ.
3. Memory/fd/CPU профиль при выбранных cap, распределённом потоке IP и медленных клиентах.
4. SIGTERM во время read/write и заполненной очереди; корректность JSONL после успешного drain.
5. Docker build/runtime, systemd sandbox и исходные IP после вашей NAT/network topology.
6. `promtool check config/rules` и `promtool test rules` для bundled alert rules.
7. Свежий RustSec scan, container scan, лицензии/SBOM и secret scan перед release.

Fuzzing и независимый pentest в этой ревизии не проводились.
Не публикуйте вымышленные результаты нагрузочных испытаний, проценты coverage или badges passing.
