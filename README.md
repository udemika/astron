# AstraG (Astasy — на базе `astron`) — Нативный однофайловый C-сервер цифрового ТВ и IPTV

Автономный однофайловый сервер приёма, буферизации и раздачи цифровых телевизионных потоков (**MPEG-TS / HLS / HTTP / HTTPS / UDP / RTP**) с встроенной веб-панелью управления на базе логики репозитория **`udemika/astron`**, переписанный полностью на чистом **C** (исходники в `c_src/`).

### Ключевые особенности сборки `astasy` (из `astron`)
- **Один полностью статический ELF-бинарник `astrag` (~4.6 МБ, `musl + OpenSSL + zlib` внутри)** — никаких зависимостей Python, `fastapi`, `uvicorn`, `pip`, `libssl.so.3`, `glibc` и распаковки в `/opt/astrag`. Работает «из коробки» на любом Linux `x86_64` (Ubuntu 18.04 / 20.04 / 22.04 / 24.04 LTS, Debian 10 / 11 / 12+, CentOS / AlmaLinux / Rocky, Alpine).
- **Двойная HLS-буферизация из `astron` (`cseg` + `oseg_t->data`)** — каждый HLS-сегмент собирается в собственный независимый буфер с префиксом PAT/PMT, поэтому медленные HLS-клиенты не теряют сегменты при перезаписи кольцевого буфера канала (`ch->ring`), а сам `ch->ring` держит компактное окно (`max(8s, GOP + 3.5s)`).
- **Встроенный веб-интерфейс** — сжатые gzip-ресурсы (`index.html`, `mod.js`, `account.html`, `favicon.png`) вшиты внутрь бинарника (`c_src/www_embed.h`).
- **Режим «По запросу» (`IN_IDLE`)** — каналы без зрителей и активного `output` находятся в статусе `Inactive` (0% CPU, 0 МБ буфера), мгновенно включаются при открытии `/play/<id>` и засыпают через 20 сек после ухода последнего зрителя.
- **Сквозной прокси кластера** — синхронизация каналов с удалённых узлов (`Settings → Servers`) и проксирование потоков/управления.

---

## Установка на сервер (любой Linux `x86_64`: Ubuntu 18.04–24.04, Debian 10–12+, CentOS)

### Вариант 1: Установка одним бинарником `astrag` (рекомендуется, как в Cesbo Astra)

Скачайте готовый нативный ELF-бинарник `astrag` из репозитория `udemika/astasy` в `/usr/bin/astrag`, сделайте его исполняемым и зарегистрируйте системный сервис:

```bash
sudo curl -Lo /usr/bin/astrag https://raw.githubusercontent.com/udemika/astasy/main/astrag
sudo chmod +x /usr/bin/astrag
sudo astrag init 8000
sudo systemctl start astrag
sudo systemctl enable astrag
```

#### То же самое одной командой (быстрая установка и автозапуск):

```bash
sudo curl -Lo /usr/bin/astrag https://raw.githubusercontent.com/udemika/astasy/main/astrag && sudo chmod +x /usr/bin/astrag && sudo astrag init 8000 --start
```

> В `htop` работает один нативный процесс **`astrag`**. Никакие пакеты `python3-*` и `/opt/astrag` не устанавливаются. Все настройки и каналы в `/etc/astrag/astrag.conf` полностью совместимы и сохраняются при обновлении.

---

### Вариант 2: Быстрая установка через `install.sh`

```bash
curl -fsSL https://raw.githubusercontent.com/udemika/astasy/main/install.sh | sudo bash -s -- --start --port 8000
```

---

### Вариант 3: Сборка из исходников C (`c_src/`)

```bash
sudo apt-get update && sudo apt-get install -y gcc make libssl-dev zlib1g-dev
git clone --depth 1 https://github.com/udemika/astasy.git
cd astasy/c_src
make
sudo install -m 0755 astrag /usr/bin/astrag
sudo astrag init 8000 --start
```

---

## Вход в веб-интерфейс

Откройте в браузере:

```text
http://<IP_ВАШЕГО_СЕРВЕРА>:8000/
```

Данные для входа по умолчанию:
- **Логин**: `admin`
- **Пароль**: `admin`

---

## Управление сервисом и конфигурацией

```bash
# Управление systemd
sudo systemctl start astrag
sudo systemctl stop astrag
sudo systemctl restart astrag
sudo systemctl status astrag
sudo journalctl -u astrag -f

# Второй независимый экземпляр на другом порту (например, 8001):
sudo astrag init 8001 --start
sudo astrag remove 8001 --purge

# Сброс пароля администратора через консоль:
sudo astrag reset-password admin НовыйПароль123
sudo systemctl restart astrag

# Обновление бинарника:
sudo curl -Lo /usr/bin/astrag https://raw.githubusercontent.com/udemika/astasy/main/astrag && sudo chmod +x /usr/bin/astrag && sudo astrag init 8000 --start && sudo systemctl restart astrag

# Полное удаление:
sudo astrag remove --purge
```
