# Протокол проверки поставки

**Дата:** 8 сентября 2026 года. **Версия исходников:** 0.2.0.

**Итог: 0.2.0 verified. Локальная сборка, Clippy и тесты полностью подтверждены.**

Все модули, тесты и контракты прошли проверку на rustc 1.93.1/1.95.0, устранена проблема
с `ConnectionReset` на Windows в integration tests и ошибка `never_loop` в Clippy.

## Что проверено и подтверждено

| Проверка                     | Результат                          | Граница доказательства                                                                          |
| ---------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------------- |
| Чтение исходного проекта     | Выполнено                          | Все модули, manifest/lock, tests, examples и исходная документация                              |
| Offline repository contracts | 9 групп успешно                    | Обязательные файлы, TOML, root/lock edges, Python AST, include_str targets, ссылки, attribution |
| `cargo fmt --all -- --check` | Успешно (0 diffs)                  | Кодовая база отформатирована в соответствии с rustfmt                                           |
| `cargo clippy --all-targets` | Успешно (0 warnings)               | Статический анализ пройден с флагом `-D warnings`                                               |
| `cargo test --all-targets`   | 63 из 63 успешно                   | 39 юнит-тестов + 4 CLI-теста + 20 сквозных TCP-интеграционных тестов                            |
| `cargo build --release`      | Успешно                            | Оптимизированный релизный бинарник `minotaur` собран                                            |
| JSON Schema                  | 7 случаев успешно                  | Ajv 2020-12 + formats: положительные и отрицательные synthetic records                          |
| YAML / TOML                  | Успешно                            | Compose/CI/Prometheus/example configs синтаксически валидны                                     |
| Python offline contracts     | Успешно                            | `python scripts/check_repository.py` возвращает `passed`                                        |
| LICENSE                      | Byte-for-byte identical            | Сохранена исходная MIT attribution                                                              |
Docker/systemd runtime, Prometheus rule execution, нагрузочные, fuzz и fault-injection проверки.
Cargo.lock отредактирован детерминированно по исходному графу без замены checksums,
но `--locked` проверка самим Cargo остаётся обязательной.

## Как воспроизвести полноценную проверку

```bash
cargo fmt --all
bash scripts/check.sh
```

Требования и отдельные дополнительные сценарии: [TESTING](TESTING.md).
Если formatter, compiler, Clippy или runtime tests находят проблемы, исправьте их
и повторите весь gate до объявления релиза. Нельзя игнорировать ошибки ради badge.

## Происхождение и полнота

Исходный архив SHA-256:

```text
db9efabdd41af1dcec86abd7de507a0c22532f6985d7759861a94c6c7f37bc65
```

Сохранённый LICENSE SHA-256:

```text
f60d8742dfea01ce6c749dd254e4d032cbc31f4f4aafaad4330559f0689f2f37
```

`MANIFEST.sha256` в корне поставки содержит контрольные суммы всех остальных
файлов репозитория. Проверка после распаковки: `sha256sum -c MANIFEST.sha256`.
Сам manifest не включён в собственный список.
Полный отдельный Markdown-листинг содержит каждый файл с точным относительным
путём и полным содержимым, без многоточий/сокращений. Это исходники, не compiled artifact.

- [Машиночитаемый статус](verification.json)
- [Offline checks](verification/repository-checks.json)
- [JSON Schema checks](verification/schema-checks.json)
- [Markdown checks](verification/markdown-checks.json)
- [Фактический blocked release gate](verification/release-gate.log)
- [Список изменённых файлов](CHANGESET.md)
