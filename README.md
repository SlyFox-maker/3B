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

Подставной TLS SNI задаётся переменной `NFQWS_FAKE_SNI`. В примерах используется маркер `sni=<FAKE_SNI>`, который заменяется при сборке временного конфига.

## Тестер и поиск стратегий

Единый wrapper читает `NFQWS_ENGINE` и запускает совместимый официальный тестер: `blockcheck.sh` для nfqws1 или `blockcheck2.sh` для nfqws2. Текущая стратегия предварительно останавливается, полный вывод сохраняется в `logs/tests/`.

```bash
sudo ./test-strategies.sh youtube.com googlevideo.com
```

Без аргументов тестер интерактивно спросит домены. Параметры поиска задаются в `.env`: `STRATEGY_TEST_LEVEL=quick|standard|force`, `STRATEGY_TEST_REPEATS`, `STRATEGY_TEST_IPV`, `STRATEGY_TEST_PARALLEL` и `STRATEGY_TEST_BATCH`.

Результаты поколений несовместимы: вывод nfqws1 переносится в `strategies/`, вывод nfqws2 — в `strategies2/`. После теста основной сервис намеренно остаётся остановленным, чтобы не запустить автоматически ещё не проверенную стратегию.

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
