# 3B DPI Bypass

Небольшой обвес для запуска `nfqws` на VPN-сервере. Исходящий трафик выбранных портов попадает в Linux `NFQUEUE`, обрабатывается профилями `nfqws` и затем отправляется в интернет.

Пример схемы с 3x-ui:

```text
client -> inbound (3x-ui / VLESS)
       -> outbound (freedom)
       -> NFQUEUE
       -> nfqws
       -> internet
```

> Скрипт изменяет системные правила `iptables` и должен запускаться с правами root. Перед применением на удалённом сервере сохраните текущие правила и обеспечьте резервный доступ к серверу.

## Требования

- Linux с `iptables` и поддержкой `NFQUEUE`;
- Bash, `sudo`, `ps` и `mktemp`;
- совместимый исполняемый файл `nfqws` в корне проекта;
- модули ядра `nfnetlink_queue` и `xt_connbytes`.

В репозитории находится 64-битный x86-совместимый бинарник `nfqws`. Для другой архитектуры замените его сборкой из проекта [bol-van/zapret](https://github.com/bol-van/zapret).

## Быстрый старт

После клонирования активных стратегий нет. Файлы `*.example` служат только примерами и автоматически не запускаются.

Включение примера YouTube:

```bash
cp strategies/youtube.conf.example strategies/youtube.conf
cp hostlists/youtube.txt.example hostlists/youtube.txt
chmod +x start.sh nfqws
sudo ./start.sh
```

Скрипт загружает только файлы `strategies/*.conf`. Чтобы отключить профиль, переименуйте его, например в `youtube.conf.disabled`, и перезапустите скрипт.

## WhatsApp

Подготовьте конфигурацию и IP-список:

```bash
cp strategies/whatsapp.conf.example strategies/whatsapp.conf
cp ipsets/whatsapp-ips.txt.example ipsets/whatsapp-ips.txt
cp hostlists/whatsapp.txt.example hostlists/whatsapp.txt
mkdir -p files/fake
```

Скачайте используемые примером бинарные шаблоны:

```bash
curl -L -o files/fake/quic_initial_www_google_com.bin \
  https://raw.githubusercontent.com/bol-van/zapret/master/files/fake/quic_initial_www_google_com.bin
```

Затем запустите:

```bash
sudo ./start.sh
```

IP-диапазоны и стратегии обхода меняются со временем и зависят от провайдера. Примеры не гарантируют работу в любой сети.

## Собственные стратегии

Создайте файл `strategies/name.conf`. Каждый независимый профиль рекомендуется явно начинать с `--new`:

```text
--new
--filter-tcp=443
--hostlist=./hostlists/example.txt
--dpi-desync=multisplit
--dpi-desync-split-pos=midsld
```

- `--hostlist` принимает доменные имена;
- `--ipset` принимает IP-адреса и CIDR-подсети;
- fake-файлы храните в `files/fake`;
- при добавлении новых портов обновите `NFQWS_TCP_PORTS` или `NFQWS_UDP_PORTS` в начале `start.sh`.

## Диагностика

```bash
pgrep -a nfqws
sudo iptables -t mangle -L THREEB_NFQWS -n -v --line-numbers
sudo tail -F /var/log/nfqws.log
```

Подробную отладку `--debug=1` следует включать только временно: при большом объёме трафика лог быстро растёт и обработка может замедлиться.

Скрипт исключает пакеты с fwmark `0x40000000`, чтобы созданные `nfqws` fake-пакеты не попадали в очередь повторно. По умолчанию в `NFQUEUE` направляются первые 64 исходящих TCP-пакета и 32 UDP-пакета соединения; лимиты задаются переменными `NFQWS_TCP_PACKET_LIMIT` и `NFQWS_UDP_PACKET_LIMIT`.

## Благодарности

Обработка DPI выполняется утилитой `nfqws` из проекта [Zapret](https://github.com/bol-van/zapret).
