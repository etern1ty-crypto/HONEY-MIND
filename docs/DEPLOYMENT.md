# Развёртывание и эксплуатация

## Сначала release gates

Эта поставка не прошла Rust build/runtime checks в среде подготовки.
Не разворачивайте её как доказанно production-ready artifact.
На машине с toolchain выполните [проверки](TESTING.md), включая binary smoke,
затем нагрузочные и fault-injection сценарии на изолированном стенде.

## Модель размещения

- Выделенный decoy-хост/IP в собственной или письменно согласованной внутренней сети.
- На хосте нет production credentials, SSH agent, cloud metadata tokens и полезных приложений.
- Высокие порты, non-root процесс. Management доступен только monitoring plane.
- Входящие разрешения задаются владельцем сети; исходящие подключения с decoy-хоста
  по умолчанию ограничены host/network firewall. Сам minotaur не делает callbacks.
- Согласуйте known scanners и ответственного за triage. Не исключайте NAT-адреса без понимания масштаба blind spot.

Приманка не отводит автоматически атакующего от реальных сервисов, не блокирует IP
и не гарантирует отсутствие false positives. Не размещайте её поверх реального SSH/HTTP.

## Linux / systemd

После успешного release gate, из корня репозитория:

```bash
sudo install -m 0755 target/release/minotaur /usr/local/bin/minotaur
sudo install -d -m 0755 /etc/minotaur
sudo install -m 0644 deploy/sensor.toml /etc/minotaur/minotaur.toml
sudo install -m 0644 deploy/minotaur.service /etc/systemd/system/minotaur.service
```

До старта отредактируйте `/etc/minotaur/minotaur.toml`: уникальный sensor.id,
согласованные IP/порты, site tags, retention и список scanners.
Пример слушает `0.0.0.0` на decoy-портах и loopback на management — это не firewall.

```bash
sudo /usr/local/bin/minotaur -c /etc/minotaur/minotaur.toml validate-config
sudo systemctl daemon-reload
sudo systemctl enable --now minotaur
/usr/local/bin/minotaur -c /etc/minotaur/minotaur.toml healthcheck
```

Unit использует `DynamicUser`, приватный `StateDirectory`, UMask 0077,
NoNewPrivileges, пустой capability set, system protection, memory/task/fd limits.
`MemoryMax=512M` — стартовая эксплуатационная граница, не результат измеренного benchmark.
Проверьте её под вашим трафиком и конфигурацией. Не меняйте limits вслепую.
Для портов ниже 1024 нужны отдельно согласованные capabilities/port mapping;
unit намеренно их не выдаёт и не предлагает запуск от root.

```bash
sudo systemctl status minotaur
sudo journalctl -u minotaur --since '15 minutes ago'
sudo systemctl stop minotaur
```

Session JSONL находится в `/var/lib/minotaur/honeypot.jsonl`, diagnostics — в journal.
Collector, читающему private file, выдайте минимально необходимые права через
управляемую модель доступа; не делайте файл world-readable ради удобства.

## Docker / Compose

```bash
docker compose build
docker compose up -d
docker compose exec sensor minotaur healthcheck --address 127.0.0.1:9090
```

Контейнер non-root, read-only rootfs, capabilities dropped, bounded logging driver.
Все published ports в примере привязаны к host loopback. Для реального LAN deployment
расширяйте только decoy ports на согласованный host IP, не management.

JSONL и stderr diagnostics попадают в container logging stream; collector должен
различать stdout/stderr и разбирать только JSONL stdout как session events.
Ротацию stdout выполняет Docker logging driver. Встроенная файловая ротация в этом
профиле не используется. Приватных volume с реальными секретами в контейнер не монтируйте.

Контейнерная NAT-схема может изменить видимый source IP. Если это критично,
проверьте адреса реальными соединениями на стенде и предпочтите host-native deployment
или согласованную network topology. Не обещайте оригинальный client IP после произвольного proxy/NAT.

Dockerfile использует glibc-compatible runtime image, а не `scratch`:
обычная Cargo release-сборка не доказана как полностью статический бинарник.
Теги образов не immutable; перед выпуском зафиксируйте проверенные digests и
проверьте OS-level vulnerabilities image scanner вашей организации.
Docker build/runtime и Compose smoke в среде подготовки **не выполнены**.

## Prometheus и алерты

[Конфиг scrape](../deploy/prometheus.yml), [правила](../deploy/alerts.yml),
[правила unit tests](../deploy/alerts.test.yml). Разместите файлы рядом.

```bash
cd deploy
promtool check config prometheus.yml
promtool check rules alerts.yml
promtool test rules alerts.test.yml
```

Пример scrape обращается к loopback; для центрального Prometheus настройте отдельно
защищённый monitoring path. Не включайте `allow_remote` без network policy.
Alertmanager маршрутизацию и получателей задаёт существующий monitoring stack —
секреты и фиктивные webhook endpoints в репозиторий не добавлены.

`MinotaurDecoyTouched` действует для environment=production. `up == 0`,
readiness и dropped logs контролируются отдельно. Для capture длительных сессий
connections_total растёт сразу, parsed events — при закрытии.
`increase` требует достаточного числа samples: первое событие до первого scrape
может не вызвать counter-based alert. Для гарантированной обработки каждого события
нужен корректно настроенный JSONL collector, а не только метрики.

## Retention и безопасное восстановление

- Default file retention: текущий файл + 3 архива по 10 MiB.
- Collector должен уметь работать с rename-based rotation. Нельзя одновременно
  ротировать те же файлы внешним logrotate/copytruncate.
- После power loss возможен неполный tail; сенсор явно откажется его продолжать.
  Остановите процесс, сохраните файл для разбирательства и перенесите повреждённый
  файл в изолированное хранилище. Только затем создавайте новый пустой log.
- Lock-файл может оставаться после остановки: блокировка хранится в ОС, не в факте
  существования файла. Не удаляйте `.lock`, пока жив хотя бы один writer.
- Резервные копии, экспорт и срок хранения могут расширять аудиторию данных.
  Политика доступа должна применяться и к архивам/collector, особенно в full-mode.

## Отказы и rollback

| Симптом                           | Проверка / действие                                                                                            |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Bind failed                       | Проверьте конфликт с реальным сервисом; не убивайте неизвестный процесс автоматически                          |
| Log lock error                    | Найдите второго писателя, остановите лишний process; не удаляйте lock-файл живого процесса                     |
| Writer error / процесс рестартует | Диск, quota, permissions, collector pipe, tail integrity; file/stdout errors не игнорируются                   |
| Drop counters растут              | Недостаточная sink throughput или слишком большая нагрузка; сначала диагностируйте, потом меняйте queue/limits |
| Нет алертов                       | Проверьте up, readiness, environment filter, scrape history и доступность collector                            |

При обновлении: сохранить config → validate новым бинарником → staged smoke →
остановить старый процесс → заменить binary/config → запустить → healthcheck.
Для rollback используйте отдельно сохранённый binary и совместимый config/schema;
новые ключи v0.2 неизвестны старому v0.1. Hot reload и автоматический updater отсутствуют.
