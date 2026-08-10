# 3B DPI Bypass

Обвес для запуска `nfqws` первого или второго поколения на VPN-сервере. Движок выбирается в `.env`. Трафик выбранных портов попадает в Linux `NFQUEUE`, обрабатывается профилями и отправляется в интернет.

```text
client -> inbound (3x-ui / VLESS)
       -> outbound (freedom)
       -> NFQUEUE
       -> nfqws1 или nfqws2
       -> internet
```

> Скрипт изменяет системные правила `iptables` и должен запускаться с правами root. Перед применением на удалённом сервере сохраните правила и обеспечьте резервный доступ.

## Требования

- Linux с `iptables`, conntrack и поддержкой `NFQUEUE`;
- Bash, `sudo`, `ps`, `find`, `awk`, `sed` и `mktemp`;
- модуль ядра `nfnetlink_queue`.

В репозитории находятся x86-64 бинарники обоих поколений. Режим 1 и его tester используют официальный Zapret v72.13; режим 2 и Lua-библиотеки — Zapret2 v1.0.4. Для другой архитектуры замените бинарники сборками [zapret](https://github.com/bol-van/zapret) и [zapret2](https://github.com/bol-van/zapret2).

## Выбор движка

Создайте локальную конфигурацию:

```bash
cp .env.example .env
```

Основная переменная:

```dotenv
NFQWS_ENGINE=1
```

- `1` — классический `nfqws`, стратегии из `strategies/`;
- `2` — Lua-движок `nfqws2`, стратегии из `strategies2/`.

Файлы `*.example` автоматически не запускаются. Активными считаются только `*.conf`.

## Быстрый старт nfqws1

```bash
cp strategies/youtube.conf.example strategies/youtube.conf
cp hostlists/youtube.txt.example hostlists/youtube.txt
sudo ./start.sh
```

Для WhatsApp:

```bash
cp strategies/whatsapp.conf.example strategies/whatsapp.conf
cp ipsets/whatsapp-ips.txt.example ipsets/whatsapp-ips.txt
cp hostlists/whatsapp.txt.example hostlists/whatsapp.txt
mkdir -p files/fake
curl -L -o files/fake/quic_initial_www_google_com.bin \
  https://raw.githubusercontent.com/bol-van/zapret/master/files/fake/quic_initial_www_google_com.bin
sudo ./start.sh
```

## Быстрый старт nfqws2

Установите в `.env` `NFQWS_ENGINE=2`, затем:

```bash
cp strategies2/youtube.conf.example strategies2/youtube.conf
cp hostlists/youtube.txt.example hostlists/youtube.txt
sudo ./start.sh
```

Для WhatsApp:

```bash
cp strategies2/whatsapp.conf.example strategies2/whatsapp.conf
cp ipsets/whatsapp-ips.txt.example ipsets/whatsapp-ips.txt
cp hostlists/whatsapp.txt.example hostlists/whatsapp.txt
sudo ./start.sh
```

`nfqws2` получает начало соединения в обоих направлениях. Лимиты задаются через `NFQWS2_TCP_PKT_OUT`, `NFQWS2_TCP_PKT_IN`, `NFQWS2_UDP_PKT_OUT` и `NFQWS2_UDP_PKT_IN`. Это позволяет Lua-стратегиям анализировать ответы и не отправлять всё соединение в userspace.

Для открытия NFQUEUE процессу требуется `CAP_NET_ADMIN`. По умолчанию `NFQWS2_UID=0` и `NFQWS2_GID=0`, поэтому nfqws2 остаётся root. Непривилегированный UID разрешается только для бинарника, которому администратор заранее выдал `cap_net_admin`; иначе `start.sh` завершится с понятной ошибкой до изменения firewall. Официальный tester использует собственное окружение и его `UID=1:3003` нельзя автоматически переносить в постоянный сервис на любой системе.

При старте Lua, hostlist, ipset и fake-файлы копируются в `/run/3b-nfqws2-runtime`. `nfqws2` сбрасывает root-права, поэтому не смог бы загрузить их напрямую из домашнего каталога с правами `700`.

## Управление

Повторный запуск безопасно останавливает управляемый процесс и пересоздаёт собственные цепочки. Полная остановка:

```bash
sudo ./stop.sh
```

При ошибке запуска добавленные правила удаляются автоматически. Скрипты не удаляют посторонние правила `iptables`.

Чтобы отключить стратегию, переименуйте её, например в `youtube.conf.disabled`, и перезапустите систему.

## Собственные стратегии

Конфиги поколений несовместимы:

- nfqws1 использует `--dpi-desync-*` и каталог `strategies/`;
- nfqws2 использует `--payload`, `--lua-desync` и каталог `strategies2/`.

Каждый независимый профиль начинайте с `--new`; в nfqws2 можно использовать именованный вариант `--new=name`. `--hostlist` принимает домены, `--ipset` — IP/CIDR. Порты перехвата задаются в `.env` через `NFQWS_TCP_PORTS` и `NFQWS_UDP_PORTS`.

Точная конфигурация, собранная из всех активных `*.conf`, сохраняется при каждом запуске в `logs/nfqws-effective.conf`. Именованные `--new=name` из файлов сохраняются, поэтому имя выбранного профиля видно в debug-логе.

Подставной TLS SNI задаётся переменной `NFQWS_FAKE_SNI`. В примерах используется маркер `sni=<FAKE_SNI>`, который заменяется при сборке временного конфига.

## Тестер и поиск стратегий

Единый wrapper читает `NFQWS_ENGINE` и запускает совместимый официальный тестер: `blockcheck.sh` для nfqws1 или `blockcheck2.sh` для nfqws2. Текущая стратегия предварительно останавливается, полный вывод сохраняется в `logs/tests/`.

Tester запускается из временной директории `/tmp/3b-blockcheck.*`. Это необходимо, потому что `nfqws2` сбрасывает root-права перед загрузкой Lua и не может читать проект внутри домашнего каталога с правами `700`. Временная копия удаляется при завершении или `Ctrl+C`; права домашнего каталога не ослабляются.

```bash
sudo ./test-strategies.sh youtube.com googlevideo.com
```

Без аргументов тестер интерактивно спросит домены. Параметры поиска задаются в `.env`: `STRATEGY_TEST_LEVEL=quick|standard|force`, `STRATEGY_TEST_REPEATS`, `STRATEGY_TEST_IPV`, `STRATEGY_TEST_PARALLEL` и `STRATEGY_TEST_BATCH`.

Если `STRATEGY_TEST_LEVEL`, `STRATEGY_TEST_REPEATS`, `STRATEGY_TEST_TOTAL`, `STRATEGY_TEST_STOP_AFTER_FOUND` или `STRATEGY_TEST_IP_OVERRIDES` отсутствуют либо оставлены пустыми, wrapper перед запуском интерактивно спросит их и покажет назначение каждого параметра. Нажатие Enter выбирает указанное в приглашении значение по умолчанию; для IP overrides это означает обычный DNS без подмены. Заполненные параметры берутся из `.env` без дополнительных вопросов.

Перед тестом wrapper в режиме симуляции считает объём перебора, после каждой завершённой стратегии показывает прогресс `обработано/всего`, процент, число находок и прошедшее время. В интерактивном терминале progress bar постоянно перерисовывается в нижней строке; управляющие коды в полный лог не записываются. Для `standard` и `quick` общее количество является оценкой: официальный tester может отсечь часть веток после промежуточного успеха. Отключить предварительный подсчёт можно через `STRATEGY_TEST_PROGRESS=0`.

Чтобы не повторять медленный предварительный подсчёт, его результат можно сохранить в `.env`:

```dotenv
STRATEGY_TEST_TOTAL=1000
```

При значении больше нуля симуляция пропускается, а число используется только как ориентир для progress bar. Если реальных вариантов окажется больше, тест не остановится: полоса останется на `100%`, а счётчик продолжит показывать, например, `1050/1000`. Значение `0` включает автоматический подсчёт при `STRATEGY_TEST_PROGRESS=1`.

Автоматическая корректная остановка после первой найденной стратегии:

```dotenv
STRATEGY_TEST_REPEATS=3
STRATEGY_TEST_STOP_AFTER_FOUND=1
```

Значение `1` означает не «остановиться после первой удачной попытки», а остановиться после стратегии, которая успешно прошла все три `REPEATS`. Можно указать `2`, `3` и так далее; `0` выполняет полный проход. После автостопа доменные кандидаты уже сохранены, но итоговые `SUMMARY` и `common/` не создаются.

`STRATEGY_TEST_STOP_AFTER_FOUND` — это целевое, а не обязательное минимальное количество. Например, при значении `15` tester завершится сразу после 15 полностью успешных стратегий. Если весь доступный перебор закончится на 8, запуск штатно завершится и сохранит эти 8 стратегий.

Чтобы тестировать домен через конкретный доступный frontend, не меняя SNI, предзаполните DNS-кэш tester-а:

```dotenv
STRATEGY_TEST_IP_OVERRIDES="whatsapp.com=57.144.251.32 web.whatsapp.com=57.144.251.32"
```

Результаты поколений несовместимы: вывод nfqws1 переносится в `strategies/`, вывод nfqws2 — в `strategies2/`. После теста основной сервис намеренно остаётся остановленным, чтобы не запустить автоматически ещё не проверенную стратегию.

После успешного завершения `SUMMARY` автоматически разбирается в `logs/tests/results/nfqwsN-ДАТА-ВРЕМЯ/`:

```text
domains/<domain>/tls12-ipv4.candidate.conf  первая стабильная кандидатура
domains/<domain>/tls12-ipv4.all.conf        все успешные стратегии домена
common/tls12-ipv4.candidate.conf            готовый общий кандидат для всех доменов
common/tls12-ipv4.all.conf                  все стратегии, общие для всех доменов
index.tsv                                   единый поисковый индекс
README.txt                                  описание отчёта
```

Успешные стратегии сохраняются и во время работы. Как только все настроенные попытки одной стратегии завершатся успешно, на экране появится:

```text
>>> FOUND: whatsapp.com | tls12 | ipv4
>>> SAVED: .../domains/whatsapp.com/tls12-ipv4.candidate.conf
```

Поэтому при ручном `Ctrl+C` после появления подходящего `FOUND` доменный кандидат уже записан. Для штатной остановки используйте `STRATEGY_TEST_STOP_AFTER_FOUND`: tester сам завершится сразу после полностью проверенной находки и уберёт временные правила. Полное завершение требуется только для формирования достоверного `common/` и окончательного `index.tsv`.

Кандидаты не активируются автоматически: успешная стратегия `curl` ещё должна быть просмотрена и проверена реальным приложением. Нужный `.candidate.conf` можно скопировать в `strategies/` или `strategies2/`, после чего запустить `sudo ./start.sh`.

Удобный просмотр последнего отчёта:

```bash
./show-strategies.sh
./show-strategies.sh youtube.com
```

## Диагностика

```bash
pgrep -a nfqws
pgrep -a nfqws2
sudo iptables -t mangle -L THREEB_NFQWS_OUT -n -v --line-numbers
sudo iptables -t mangle -L THREEB_NFQWS_IN -n -v --line-numbers
tail -F logs/nfqws-debug.log
```

Trace включён по умолчанию. Отключение:

```dotenv
NFQWS_TRACE=0
```

Общий размер журналов ограничен значением `LOG_MAX_BYTES` (по умолчанию 200 МБ). Fake-пакеты получают mark `0x40000000` и исключаются из повторного попадания в очередь.

## Лицензия и происхождение

Обработка DPI выполняется утилитами проектов [Zapret](https://github.com/bol-van/zapret) и [Zapret2](https://github.com/bol-van/zapret2). Лицензия vendored-компонентов Zapret2 находится в `vendor/zapret2/LICENSE.txt`.
