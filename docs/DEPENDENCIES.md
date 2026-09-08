# Зависимости и воспроизводимость

## Фактический стек

Rust 2021, Tokio/Tokio-util для TCP/tasks/cancellation; Clap для CLI;
Serde/TOML/Serde JSON для конфигурации и событий; Hyper/Hyper-util/HTTP Body Util
для management HTTP; Prometheus text exposition; Chrono и UUID для record identity;
Hex для ограниченного forensic preview. Unix-only libc используется для безопасных
open flags, без unsafe-блоков в проекте. Production `unsafe_code` запрещён.

Один исполняемый файл не означает «нет стороннего кода» или «бинарник полностью
статический». Стандартная Linux GNU-сборка требует совместимого runtime/linker ABI.
Dockerfile намеренно не использует scratch.

## Что изменено

- Версия проекта обновлена с 0.1.0 до 0.2.0; публикация crates.io/release не выполнялась.
- Toolchain зафиксирована в `rust-toolchain.toml` на 1.93.1.
  `rust-version=1.93` — консервативная заявленная граница для этого исходника,
  а не доказанный результат поиска минимального MSRV.
- В Tokio включён `io-std`, в Clap — `env`; новых функциональных runtime frameworks нет.
- Прямые unused dependencies `bytes` и `thiserror` удалены из manifest;
  они могут оставаться транзитивными, если нужны Hyper/Prometheus.
- libc, уже присутствовавший транзитивно в исходном lock, указан как Unix direct dependency.
- Prometheus `default-features=false` убирает ненужный protobuf encoder/dependency;
  используется только text metrics.
- Остальные locked versions и registry checksums исходного архива сохранены.

## Известное advisory

[RUSTSEC-2024-0437](https://rustsec.org/advisories/RUSTSEC-2024-0437.html):
исходный protobuf 2.28.0 входит в затронутый диапазон; advisory указывает patched >=3.7.2.
Ненужная dependency удалена из графа, а не добавлена в ignore list.
Path от входящего TCP до уязвимого protobuf parser в исходнике не установлен.
Это исправление конкретного dependency risk, не доказательство отсутствия других CVE.

## Что означает текущий Cargo.lock

Из-за отсутствия Cargo graph обновлён детерминированно по существующему lock:
root version/edges изменены, ребро Prometheus → protobuf и ненужный protobuf node удалены.
Registry versions/checksums не выдумывались и не заменялись скачанным непроверенным кодом.
Offline script проверяет ссылки между package nodes и manifest/root agreement.
**Он не заменяет Cargo resolver.** Перед выпуском обязательно:

```bash
cargo metadata --locked --format-version 1 > target-metadata.json
cargo build --locked --release
cargo tree --locked -e features
cargo audit --deny warnings
```

Если Cargo сообщает необходимость изменить lock, выполните контролируемую
регенерацию и изучите diff, затем повторите все gates. Не убирайте `--locked`
из CI ради зелёного статуса и не заявляйте «clean dependencies» по offline parse.

## Supply chain

CI имеет read-only permissions и checkout с отключённым сохранением credentials.
Dependabot настроен на Cargo/GitHub Actions/Docker. Workflow не публикует образы,
не использует project secrets и не разворачивает сенсор в чужую сеть.
Аудит устанавливается и выполняется отдельным job. Инструменты audit и mutable image tags
тоже требуют политики pin/update в вашей организации.

## Лицензии

Исходный MIT LICENSE и copyright не изменены. Это лицензия кода проекта, а не
автоматическое перелицензирование всех crates и OS-пакетов контейнера.
До распространения binary/image сформируйте SBOM и проверьте license/license_file
пакетов из `cargo metadata` и базового образа. Полная юридическая проверка dependency
tree в среде подготовки не выполнялась; не приписывайте проекту чужие товарные знаки.
