#!/bin/sh
# auto_scan.sh — Универсальный сетевой инструмент
# Функции: проверка по ссылке, поиск подсетей ASN, авто-определение ASN по IP, пинг подсетей

# ══════════════════════════════════════════════════════
# Цвета и оформление
# ══════════════════════════════════════════════════════
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Проверка зависимостей
check_deps() {
  for cmd in curl grep ping whois awk sort cut; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "❌ Установите: $cmd"; exit 1; }
  done
}

# ══════════════════════════════════════════════════════
# ФУНКЦИЯ 1: Проверка доступности по ссылке (vless_scan)
# ══════════════════════════════════════════════════════
do_url_scan() {
  URL="$1"
  if [ -z "$URL" ]; then
    printf "🌐 Введите прямую ссылку на файл с ключами: "
    read -r URL
  fi
  [ -z "$URL" ] && { echo "❌ Ссылка не указана."; return 1; }

  TMP_DIR=$(mktemp -d)
  trap "rm -rf $TMP_DIR" EXIT
  OUT_CSV="ip_whois_results.csv"

  # ШАГ 1: Загрузка
  echo ""
  echo "🔐 ШАГ 1: Включите VPN для загрузки ключей"
  echo "══════════════════════════════════════════════════════"
  printf "   ✅ VPN включён? Нажмите Enter... "
  read -r _dummy

  echo "📥 Загружаю: $URL"
  if ! curl -sL --max-time 15 --fail "$URL" -o "$TMP_DIR/keys.txt" 2>/dev/null; then
    echo "❌ Ошибка загрузки. Проверьте ссылку и подключение."; return 1
  fi

  # Извлечение уникальных IP
  grep -oE '@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMP_DIR/keys.txt" | cut -d'@' -f2 | sort -u > "$TMP_DIR/all_ips.txt"
  TOTAL=$(wc -l < "$TMP_DIR/all_ips.txt" | tr -d ' ')
  echo "   📦 Найдено уникальных IP: $TOTAL"
  [ "$TOTAL" -eq 0 ] && { echo "❌ IP не найдены в подписке."; return 1; }

  # ШАГ 2: Пинг
  echo ""
  echo "🔓 ШАГ 2: Выключите VPN для точного пинга"
  echo "══════════════════════════════════════════════════════"
  printf "   ✅ VPN выключен? Нажмите Enter... "
  read -r _dummy

  echo "📡 Пингую хосты (таймаут 2с)..."
  > "$TMP_DIR/reachable.txt"
  COUNT=0
  while IFS= read -r ip; do
    COUNT=$((COUNT + 1))
    printf "\r   ⏳ [%3d/%3d] %-15s" "$COUNT" "$TOTAL" "$ip"
    if ping -c 1 -W 2 "$ip" >/dev/null 2>&1; then
      echo "$ip" >> "$TMP_DIR/reachable.txt"
    fi
  done < "$TMP_DIR/all_ips.txt"
  echo ""
  REACH=$(wc -l < "$TMP_DIR/reachable.txt" | tr -d ' ')
  echo "   ✅ Доступных: $REACH из $TOTAL"
  [ "$REACH" -eq 0 ] && { echo "⚠️ Ни один хост не ответил. Завершаю."; return 0; }

  # ШАГ 3: Whois
  echo ""
  echo "🔐 ШАГ 3: Включите VPN для whois-запросов"
  echo "══════════════════════════════════════════════════════"
  printf "   ✅ VPN включён? Нажмите Enter для запуска whois... "
  read -r _dummy

  echo "IP;ORG;COUNTRY;ASN;SUBNET" > "$OUT_CSV"
  COUNT=0
  while IFS= read -r ip; do
    COUNT=$((COUNT + 1))
    printf "\r   ⏳ [%3d/%3d] %s" "$COUNT" "$REACH" "$ip"

    RAW=$(timeout 10 whois -H "$ip" 2>/dev/null | tr -d '\r')

    if [ -z "$RAW" ]; then
      echo "$ip;Timeout;-;-;${ip%.*}.0/24" >> "$OUT_CSV"
      continue
    fi

    # === Умный парсинг (фильтр регистраторов) ===
    REGEX_IGNORE='RIPE Network Coordination Centre|^RIPE$|ARIN|APNIC|IANA|RIPE NCC|Legacy|ERX'

    # 1. Ищем org-name, пропуская RIPE/ARIN/APNIC
    ORG=$(echo "$RAW" | grep -iE '^org-name:|^organisation:|^orgname:|^Organization:' | sed 's/^[^:]*:[[:space:]]*//' | grep -ivE "$REGEX_IGNORE" | tail -n 1 | tr -d '\n')

    # 2. Если только регистратор — пробуем netname
    if [ -z "$ORG" ]; then
      NETNAME=$(echo "$RAW" | grep -iE '^netname:|^NetName:' | sed 's/^[^:]*:[[:space:]]*//' | grep -ivE "$REGEX_IGNORE" | tail -n 1 | tr -d '\n')
      [ -n "$NETNAME" ] && ORG="$NETNAME"
    fi

    # 3. Если всё ещё пусто — берём descr
    if [ -z "$ORG" ]; then
      DESCR=$(echo "$RAW" | grep -iE '^descr:|^Description:' | sed 's/^[^:]*:[[:space:]]*//' | grep -ivE "$REGEX_IGNORE" | tail -n 1 | tr -d '\n')
      [ -n "$DESCR" ] && ORG="$DESCR"
    fi

    # 4. Если вообще ничего нет
    [ -z "$ORG" ] && ORG="Legacy/Unassigned"

    ASN=$(echo "$RAW" | grep -iE '^origin:|^aut-num:|^OriginAS:' | grep -oiE 'AS[0-9]+' | tail -n 1 | tr -d '\n')
    [ -z "$ASN" ] && ASN="-"

    CC=$(echo "$RAW" | grep -iE '^country:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\n' | tr '[:lower:]' '[:upper:]')
    [ -z "$CC" ] && CC="Unknown"

    SUBNET="${ip%.*}.0/24"
    echo "$ip;$ORG;$CC;$ASN;$SUBNET" >> "$OUT_CSV"
    sleep 0.1
  done < "$TMP_DIR/reachable.txt"

  echo ""
  echo "✅ Готово! Результат: $OUT_CSV"
  echo ""

  # Красивый вывод
  echo "📊 Топ-15 доступных IP:"
  printf "%-16s | %-25s | %-6s | %-10s | %s\n" "IP" "ВЛАДЕЛЕЦ" "СТР" "ASN" "ПОДСЕТЬ"
  printf "%s\n" "──────────────────────────────────────────────────────────────────────────────"
  tail -n +2 "$OUT_CSV" | head -15 | while IFS=';' read -r ip org cc asn subnet; do
    printf "%-16s | %-25s | %-6s | %-10s | %s\n" "$ip" "$(echo "$org" | cut -c1-25)" "$cc" "$asn" "$subnet"
  done
  printf "%s\n" "──────────────────────────────────────────────────────────────────────────────"

  echo ""
  echo "📈 Топ-10 провайдеров:"
  tail -n +2 "$OUT_CSV" | cut -d';' -f2 | sort | uniq -c | sort -rn | head -10 | while read -r cnt name; do
    printf "   • %3d IP — %s\n" "$cnt" "$name"
  done
}

# ══════════════════════════════════════════════════════
# ФУНКЦИЯ 2: Получение подсетей по ASN
# ══════════════════════════════════════════════════════
do_asn_lookup() {
  ASN_INPUT="$1"
  if [ -z "$ASN_INPUT" ]; then
    printf "🌐 Введите ASN (например, 214822 или AS214822): "
    read -r ASN_INPUT
  fi
  [ -z "$ASN_INPUT" ] && { echo "❌ ASN не указан"; return 1; }

  # Нормализация
  ASN_NUM=$(echo "$ASN_INPUT" | sed 's/^[aA][sS]*//; s/[^0-9]//g')
  [ -z "$ASN_NUM" ] && { echo "❌ Неверный формат ASN"; return 1; }
  ASN="AS${ASN_NUM}"

  echo "🔍 Поиск подсетей для $ASN через RIPE NCC..."

  echo "📡 Выполняю запрос: whois -h whois.ripe.net -- \"-i origin $ASN -T route\""
  RAW=$(whois -h whois.ripe.net -- "-i origin $ASN -T route" 2>&1)

  # Отладка
  echo "🔎 Ответ whois (первые 10 строк):"
  echo "$RAW" | head -10
  echo "..."

  ROUTE_LINES=$(echo "$RAW" | grep -c '^route:' || true)
  echo "📊 Найдено строк 'route:': $ROUTE_LINES"

  if [ "$ROUTE_LINES" -eq 0 ]; then
    echo "❌ Не найдено маршрутов для $ASN в базе RIPE"
    echo ""
    echo "💡 Проверьте вручную:"
    echo "   whois -h whois.ripe.net -- \"-i origin $ASN -T route\""
    echo "   https://bgp.he.net/$ASN"
    return 1
  fi

  # Извлекаем подсети
  TMP_SUBNETS="/tmp/subnets_$$.txt"
  echo "$RAW" | grep -E '^route:' | awk '{print $2}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' | sort -u > "$TMP_SUBNETS"

  COUNT=$(wc -l < "$TMP_SUBNETS" | tr -d ' ')
  OUT_FILE="${ASN}_subnets.txt"

  echo ""
  echo "✅ Найдено $COUNT подсетей:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  cat -n "$TMP_SUBNETS"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  cp "$TMP_SUBNETS" "$OUT_FILE"
  echo "💾 Сохранено в: $OUT_FILE"

  echo ""
  echo "📊 Распределение по размеру:"
  awk -F/ '{print "/"$2}' "$TMP_SUBNETS" | sort -n | uniq -c | awk '{printf "   • %3d подсетей /%s\n", $1, $2}'

  rm -f "$TMP_SUBNETS"

  echo ""
  echo "💡 Использование: while read -r subnet; do ... done < $OUT_FILE"

  # Предложение пропинговать
  echo ""
  printf "🔔 Хотите пропинговать найденные подсети? (y/n): "
  read -r PING_CHOICE
  if [ "$PING_CHOICE" = "y" ] || [ "$PING_CHOICE" = "Y" ] || [ "$PING_CHOICE" = "д" ] || [ "$PING_CHOICE" = "Д" ]; then
    do_ping_subnets "$OUT_FILE"
  fi
}

# ══════════════════════════════════════════════════════
# ФУНКЦИЯ 3: Определение ASN по IP и поиск подсетей
# ══════════════════════════════════════════════════════
do_ip_to_asn() {
  IP_INPUT="$1"
  if [ -z "$IP_INPUT" ]; then
    printf "🌐 Введите IP-адрес (например, 8.8.8.8): "
    read -r IP_INPUT
  fi
  [ -z "$IP_INPUT" ] && { echo "❌ IP не указан"; return 1; }

  # Валидация IP
  echo "$IP_INPUT" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || { echo "❌ Неверный формат IP"; return 1; }

  echo "🔍 Определяю оператора для IP: $IP_INPUT ..."

  RAW=$(whois -H "$IP_INPUT" 2>/dev/null | tr -d '\r')

  if [ -z "$RAW" ]; then
    echo "❌ Не удалось получить whois-данные для $IP_INPUT"
    return 1
  fi

  # Извлекаем информацию
  REGEX_IGNORE='RIPE Network Coordination Centre|^RIPE$|ARIN|APNIC|IANA|RIPE NCC|Legacy|ERX'

  ORG=$(echo "$RAW" | grep -iE '^org-name:|^organisation:|^orgname:|^Organization:' | sed 's/^[^:]*:[[:space:]]*//' | grep -ivE "$REGEX_IGNORE" | tail -n 1 | tr -d '\n')
  [ -z "$ORG" ] && ORG=$(echo "$RAW" | grep -iE '^netname:|^NetName:' | sed 's/^[^:]*:[[:space:]]*//' | grep -ivE "$REGEX_IGNORE" | tail -n 1 | tr -d '\n')
  [ -z "$ORG" ] && ORG=$(echo "$RAW" | grep -iE '^descr:' | sed 's/^[^:]*:[[:space:]]*//' | grep -ivE "$REGEX_IGNORE" | head -1 | tr -d '\n')
  [ -z "$ORG" ] && ORG="Неизвестно"

  ASN=$(echo "$RAW" | grep -iE '^origin:|^aut-num:|^OriginAS:' | grep -oiE 'AS[0-9]+' | tail -n 1 | tr -d '\n')
  CC=$(echo "$RAW" | grep -iE '^country:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\n' | tr '[:lower:]' '[:upper:]')
  [ -z "$CC" ] && CC="?"

  INETNUM=$(echo "$RAW" | grep -iE '^inetnum:|^NetRange:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\n')

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "📋 Информация об IP: $IP_INPUT"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "   🏢 Оператор:  %s\n" "$ORG"
  printf "   🌍 Страна:    %s\n" "$CC"
  printf "   🔢 ASN:       %s\n" "${ASN:-не определён}"
  printf "   📡 Диапазон:  %s\n" "${INETNUM:-не определён}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if [ -z "$ASN" ]; then
    echo ""
    echo "⚠️ ASN не удалось определить автоматически."
    printf "   Введите ASN вручную (или Enter для отмены): "
    read -r ASN
    [ -z "$ASN" ] && return 0
  fi

  echo ""
  printf "🔔 Найти все подсети оператора $ASN? (y/n): "
  read -r CHOICE
  if [ "$CHOICE" = "y" ] || [ "$CHOICE" = "Y" ] || [ "$CHOICE" = "д" ] || [ "$CHOICE" = "Д" ]; then
    do_asn_lookup "$ASN"
  fi
}

# ══════════════════════════════════════════════════════
# ФУНКЦИЯ 4: Пинг подсетей из файла
# ══════════════════════════════════════════════════════
do_ping_subnets() {
  FILE_INPUT="$1"

  if [ -z "$FILE_INPUT" ]; then
    echo "📁 Доступные файлы подсетей:"
    FOUND=0
    for f in *_subnets.txt; do
      if [ -f "$f" ]; then
        CNT=$(wc -l < "$f" | tr -d ' ')
        printf "   📄 %s (%s подсетей)\n" "$f" "$CNT"
        FOUND=$((FOUND + 1))
      fi
    done
    if [ "$FOUND" -eq 0 ]; then
      echo "   ⚠️ Файлы подсетей не найдены. Сначала выполните поиск по ASN."
      return 1
    fi
    echo ""
    printf "📂 Введите имя файла: "
    read -r FILE_INPUT
  fi

  [ -z "$FILE_INPUT" ] && { echo "❌ Файл не указан"; return 1; }
  [ ! -f "$FILE_INPUT" ] && { echo "❌ Файл не найден: $FILE_INPUT"; return 1; }

  TOTAL=$(wc -l < "$FILE_INPUT" | tr -d ' ')
  echo ""
  echo "📡 Пинг подсетей из: $FILE_INPUT ($TOTAL подсетей)"
  echo "   Перебор всех хостов в подсети до первого ответа"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  ALIVE=0
  DEAD=0
  COUNT=0
  RESULT_FILE="/tmp/ping_results_$$.txt"
  > "$RESULT_FILE"

  while IFS= read -r subnet; do
    echo "$subnet" | grep -qE '^[0-9]' || continue
    COUNT=$((COUNT + 1))

    # Извлекаем IP и маску CIDR
    NET_IP=$(echo "$subnet" | cut -d'/' -f1)
    CIDR=$(echo "$subnet" | cut -d'/' -f2)

    # Вычисляем количество хостов по маске CIDR
    # Кол-во хостов = 2^(32-CIDR) - 2 (без network и broadcast)
    HOST_BITS=$((32 - CIDR))
    if [ "$HOST_BITS" -le 0 ]; then
      # /32 — один хост
      MAX_HOST=1
      START_HOST=0
    elif [ "$HOST_BITS" -eq 1 ]; then
      # /31 — 2 хоста (point-to-point)
      MAX_HOST=1
      START_HOST=0
    else
      # Обычная подсеть: пропускаем .0 (network) и .broadcast
      TOTAL_IPS=1
      b=0
      while [ "$b" -lt "$HOST_BITS" ]; do
        TOTAL_IPS=$((TOTAL_IPS * 2))
        b=$((b + 1))
      done
      MAX_HOST=$((TOTAL_IPS - 2))  # без network и broadcast
      START_HOST=1
    fi

    # Извлекаем октеты базового IP
    O1=$(echo "$NET_IP" | cut -d'.' -f1)
    O2=$(echo "$NET_IP" | cut -d'.' -f2)
    O3=$(echo "$NET_IP" | cut -d'.' -f3)
    O4=$(echo "$NET_IP" | cut -d'.' -f4)

    # Вычисляем базовый IP как число
    IP_NUM=$(( (O1 * 16777216) + (O2 * 65536) + (O3 * 256) + O4 ))

    FOUND_HOST=0
    FOUND_IP=""
    CHECKED=0

    # Перебираем все хосты в подсети (.1 до .MAX_HOST)
    i=$START_HOST
    while [ "$i" -le "$MAX_HOST" ]; do
      # Вычисляем IP хоста
      H_NUM=$((IP_NUM + i))
      H_O1=$(( (H_NUM / 16777216) % 256 ))
      H_O2=$(( (H_NUM / 65536) % 256 ))
      H_O3=$(( (H_NUM / 256) % 256 ))
      H_O4=$(( H_NUM % 256 ))
      TRY_IP="${H_O1}.${H_O2}.${H_O3}.${H_O4}"

      CHECKED=$((CHECKED + 1))
      printf "\r   ⏳ [%3d/%3d] %-18s → %-15s [%d/%d]       " "$COUNT" "$TOTAL" "$subnet" "$TRY_IP" "$CHECKED" "$MAX_HOST"

      if timeout 0.5 ping -c 1 -W 1 "$TRY_IP" >/dev/null 2>&1; then
        FOUND_HOST=1
        FOUND_IP="$TRY_IP"
        break
      fi
      i=$((i + 1))
    done

    if [ "$FOUND_HOST" -eq 1 ]; then
      STATUS="ALIVE"
      ALIVE=$((ALIVE + 1))
      printf "\r   ✅ [%3d/%3d] %-18s → %-15s  найден [%d/%d]       " "$COUNT" "$TOTAL" "$subnet" "$FOUND_IP" "$CHECKED" "$MAX_HOST"
    else
      STATUS="DOWN"
      FOUND_IP="-"
      DEAD=$((DEAD + 1))
      printf "\r   ❌ [%3d/%3d] %-18s → все %d хостов недоступны       " "$COUNT" "$TOTAL" "$subnet" "$MAX_HOST"
    fi

    echo "$subnet;$FOUND_IP;$STATUS" >> "$RESULT_FILE"
  done < "$FILE_INPUT"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "📊 Результаты пинга:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "   ✅ Доступны:   %d\n" "$ALIVE"
  printf "   ❌ Недоступны: %d\n" "$DEAD"
  printf "   📊 Всего:      %d\n" "$COUNT"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  echo ""
  echo "📋 Детальный отчёт:"
  printf "%-22s | %-18s | %s\n" "ПОДСЕТЬ" "ОТВЕТИВШИЙ IP" "СТАТУС"
  printf "%s\n" "──────────────────────────────────────────────────────────"
  while IFS=';' read -r subnet pip status; do
    if [ "$status" = "ALIVE" ]; then
      printf "%-22s | %-18s | ✅ %s\n" "$subnet" "$pip" "$status"
    else
      printf "%-22s | %-18s | ❌ %s\n" "$subnet" "$pip" "$status"
    fi
  done < "$RESULT_FILE"
  printf "%s\n" "──────────────────────────────────────────────────────────"

  # Сохраняем доступные подсети
  if [ "$ALIVE" -gt 0 ]; then
    ALIVE_FILE="alive_subnets_$(date +%Y%m%d_%H%M%S).txt"
    grep "ALIVE" "$RESULT_FILE" | cut -d';' -f1 > "$ALIVE_FILE"
    echo ""
    echo "💾 Доступные подсети сохранены в: $ALIVE_FILE"
  fi

  # Предложение экспорта в Obsidian
  echo ""
  printf "📝 Экспортировать отчёт в Obsidian MD? (y/n): "
  read -r MD_CHOICE
  if [ "$MD_CHOICE" = "y" ] || [ "$MD_CHOICE" = "Y" ] || [ "$MD_CHOICE" = "д" ] || [ "$MD_CHOICE" = "Д" ]; then
    export_obsidian_ping "$FILE_INPUT" "$RESULT_FILE" "$ALIVE" "$DEAD" "$COUNT"
  fi

  rm -f "$RESULT_FILE"
}

# ══════════════════════════════════════════════════════
# ФУНКЦИЯ 5: Экспорт отчёта в Obsidian MD (Mermaid граф)
# ══════════════════════════════════════════════════════
export_obsidian_ping() {
  SRC_FILE="$1"
  RESULTS="$2"
  P_ALIVE="$3"
  P_DEAD="$4"
  P_TOTAL="$5"
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
  MD_FILE="report_ping_$(date +%Y%m%d_%H%M%S).md"

  # Определяем ASN из имени файла
  ASN_NAME=$(echo "$SRC_FILE" | sed 's/_subnets.txt//' | tr '[:lower:]' '[:upper:]')

  cat > "$MD_FILE" << MDEOF
---
tags: [glaz-gora, ping, network, $ASN_NAME]
date: $TIMESTAMP
---

# 📶 Отчёт пинга подсетей: $ASN_NAME

> Источник: \`$SRC_FILE\`
> Дата: $TIMESTAMP


## 📊 Сводка

| Метрика | Значение |
|---------|----------|
| ✅ Доступны | $P_ALIVE |
| ❌ Недоступны | $P_DEAD |
| 📊 Всего | $P_TOTAL |

## 🗺️ Граф подсетей



\`\`\`mermaid
graph LR
  ASN["🏢 $ASN_NAME<br/>$P_TOTAL подсетей"]
  style ASN fill:#1a365d,stroke:#63b3ed,color:#e2e8f0
MDEOF

  # Генерируем узлы графа
  IDX=0
  while IFS=';' read -r subnet pip status; do
    echo "$subnet" | grep -qE '^[0-9]' || continue
    IDX=$((IDX + 1))
    SAFE_ID="s${IDX}"
    if [ "$status" = "ALIVE" ]; then
      echo "  ASN --> ${SAFE_ID}[\"✅ ${subnet}<br/>${pip}\"]" >> "$MD_FILE"
      echo "  style ${SAFE_ID} fill:#2d6a4f,stroke:#22c55e,color:#fff" >> "$MD_FILE"
    else
      echo "  ASN --> ${SAFE_ID}[\"❌ ${subnet}\"]" >> "$MD_FILE"
      echo "  style ${SAFE_ID} fill:#6b0f1a,stroke:#fb7185,color:#fff" >> "$MD_FILE"
    fi
  done < "$RESULTS"

  echo '```' >> "$MD_FILE"

  # Таблица деталей
  cat >> "$MD_FILE" << 'MDEOF2'

## 📋 Детальная таблица

| # | Подсеть | Ответивший IP | Статус |
|---|---------|---------------|--------|
MDEOF2

  IDX=0
  while IFS=';' read -r subnet pip status; do
    IDX=$((IDX + 1))
    if [ "$status" = "ALIVE" ]; then
      echo "| $IDX | \`$subnet\` | \`$pip\` | ✅ Доступна |" >> "$MD_FILE"
    else
      echo "| $IDX | \`$subnet\` | — | ❌ Недоступна |" >> "$MD_FILE"
    fi
  done < "$RESULTS"

  echo "" >> "$MD_FILE"
  echo "---" >> "$MD_FILE"
  echo "*Сгенерировано: Glaz Gora Scanner*" >> "$MD_FILE"

  echo "💾 Obsidian отчёт сохранён: $MD_FILE"
}

# Экспорт полного отчёта URL-скана в Obsidian
export_obsidian_url() {
  CSV_FILE="$1"
  [ ! -f "$CSV_FILE" ] && { echo "❌ CSV не найден: $CSV_FILE"; return 1; }

  TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
  MD_FILE="report_scan_$(date +%Y%m%d_%H%M%S).md"

  TOTAL_IPS=$(tail -n +2 "$CSV_FILE" | wc -l | tr -d ' ')

  mermaid_escape() {
    # Mermaid ломается на спецсимволах внутри label в ["..."]
    # Заменяем " на ', убираем #, & -> and, ; -> запятая
    printf '%s' "$1" | tr -d '\r' | sed "s/\"/'/g; s/#//g; s/&/and/g; s/;/,/g"
  }



  # ─────────────────────────────────────────────────────
  # Подготовка данных: провайдеры с подсчётом и подсети
  # ─────────────────────────────────────────────────────
  TMP_PROV_CNT="/tmp/gg_prov_cnt_$$.txt"
  TMP_PROV_LIST="/tmp/gg_prov_list_$$.txt"
  tail -n +2 "$CSV_FILE" | awk -F';' 'NF>=2 && $2!="" {print $2}' | sort | uniq -c | sort -rn > "$TMP_PROV_CNT"
  tail -n +2 "$CSV_FILE" | awk -F';' 'NF>=2 && $2!="" {print $2}' | sort -u > "$TMP_PROV_LIST"
  TOTAL_PROVS=$(wc -l < "$TMP_PROV_LIST" | tr -d ' ')
  TOTAL_SUBNETS=$(tail -n +2 "$CSV_FILE" | awk -F';' '{print $2";"$5}' | sort -u | wc -l | tr -d ' ')

  cat > "$MD_FILE" << MDEOF
---
tags: [glaz-gora, url-scan, network]
date: $TIMESTAMP
---

# 🌐 Отчёт сканирования по ссылке

> Источник: \`$CSV_FILE\`
> Дата: $TIMESTAMP
> Всего IP: $TOTAL_IPS | Провайдеров: $TOTAL_PROVS | Уникальных подсетей: $TOTAL_SUBNETS

## 🗺️ Граф: Провайдеры

\`\`\`mermaid
graph LR
  SRC["🔗 Источник<br/>${TOTAL_IPS} IP"]
MDEOF

  # ── Граф 1: Источник → Провайдеры (компактный) ──
  while read -r cnt prov; do
    [ -z "$prov" ] && continue
    SAFE_PROV=$(echo "$prov" | tr ' /.()' '_____' | tr -cd 'a-zA-Z0-9_')
    [ -z "$SAFE_PROV" ] && SAFE_PROV="prov"
    PROV_LABEL=$(echo "$prov" | cut -c1-35)
    PROV_LABEL_ESC=$(mermaid_escape "$PROV_LABEL")
    echo "  SRC --> P_${SAFE_PROV}[\"🏢 ${PROV_LABEL_ESC}<br/>${cnt} IP\"]" >> "$MD_FILE"
  done < "$TMP_PROV_CNT"

  # Стили — топ-3 провайдера выделены цветом
  TOP_I=0
  while read -r cnt prov; do
    TOP_I=$((TOP_I + 1))
    [ "$TOP_I" -gt 3 ] && break
    SAFE_PROV=$(echo "$prov" | tr ' /.()' '_____' | tr -cd 'a-zA-Z0-9_')
    [ -z "$SAFE_PROV" ] && SAFE_PROV="prov"
    echo "  style P_${SAFE_PROV} fill:#1a365d,stroke:#63b3ed,color:#e2e8f0" >> "$MD_FILE"
  done < "$TMP_PROV_CNT"

  echo '```' >> "$MD_FILE"

  # ── Граф 2: Провайдеры → Подсети (топ-10 провайдеров) ──
  echo '' >> "$MD_FILE"
  echo '## 🗺️ Граф: Подсети по провайдерам' >> "$MD_FILE"
  echo '' >> "$MD_FILE"
  echo '```mermaid' >> "$MD_FILE"
  echo 'graph LR' >> "$MD_FILE"

  PROV_I=0
  while read -r cnt prov; do
    [ -z "$prov" ] && continue
    PROV_I=$((PROV_I + 1))
    [ "$PROV_I" -gt 10 ] && break
    SAFE_PROV=$(echo "$prov" | tr ' /.()' '_____' | tr -cd 'a-zA-Z0-9_')
    [ -z "$SAFE_PROV" ] && SAFE_PROV="prov"
    PROV_LABEL=$(echo "$prov" | cut -c1-35)
    PROV_LABEL_ESC=$(mermaid_escape "$PROV_LABEL")

    echo "  P_${SAFE_PROV}[\"🏢 ${PROV_LABEL_ESC}<br/>${cnt} IP\"]" >> "$MD_FILE"

    # Уникальные подсети этого провайдера
    TMP_SUB="/tmp/gg_sub_${SAFE_PROV}_$$.txt"
    tail -n +2 "$CSV_FILE" | awk -F';' -v p="$prov" '$2==p {print $5}' | sort | uniq -c | sort -rn > "$TMP_SUB"
    while read -r scnt subnet; do
      [ -z "$subnet" ] && continue
      SUBNET_SAFE=$(echo "${SAFE_PROV}_${subnet}" | tr './' '__' | tr -cd 'a-zA-Z0-9_')
      if [ "$scnt" -gt 1 ]; then
        echo "  P_${SAFE_PROV} --> S_${SUBNET_SAFE}[\"${subnet}<br/>${scnt} IP\"]" >> "$MD_FILE"
      else
        echo "  P_${SAFE_PROV} --> S_${SUBNET_SAFE}[\"${subnet}\"]" >> "$MD_FILE"
      fi
    done < "$TMP_SUB"
    rm -f "$TMP_SUB"
  done < "$TMP_PROV_CNT"

  echo '```' >> "$MD_FILE"

  rm -f "$TMP_PROV_CNT" "$TMP_PROV_LIST"

  # Таблица
  cat >> "$MD_FILE" << 'MDEOF2'

## 📋 Все IP

| IP | Провайдер | Страна | ASN | Подсеть |
|----|-----------|--------|-----|--------|
MDEOF2

  tail -n +2 "$CSV_FILE" | while IFS=';' read -r ip org cc asn subnet; do
    echo "| \`$ip\` | $org | $cc | $asn | \`$subnet\` |" >> "$MD_FILE"
  done

  # Топ провайдеров
  echo "" >> "$MD_FILE"
  echo "## 📈 Топ провайдеров" >> "$MD_FILE"
  echo "" >> "$MD_FILE"
  tail -n +2 "$CSV_FILE" | cut -d';' -f2 | sort | uniq -c | sort -rn | head -10 | while read -r cnt name; do
    echo "- **${name}** — ${cnt} IP" >> "$MD_FILE"
  done

  echo "" >> "$MD_FILE"
  echo "---" >> "$MD_FILE"
  echo "*Сгенерировано: Glaz Gora Scanner*" >> "$MD_FILE"

  echo "💾 Obsidian отчёт сохранён: $MD_FILE"
}

# Интерактивный экспорт
do_export_obsidian() {
  echo "📝 Экспорт отчёта в Obsidian MD"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "   1) 📊 Экспорт URL-скана (ip_whois_results.csv)"
  echo "   2) 📶 Экспорт пинга подсетей (выбрать файл)"
  echo ""
  printf "   👉 Выберите [1-2]: "
  read -r EX_CHOICE

  case "$EX_CHOICE" in
    1)
      if [ -f "ip_whois_results.csv" ]; then
        export_obsidian_url "ip_whois_results.csv"
      else
        echo "❌ Файл ip_whois_results.csv не найден. Сначала выполните скан."
      fi
      ;;
    2)
      echo "📁 Доступные файлы результатов:"
      for f in alive_subnets_*.txt *_subnets.txt; do
        [ -f "$f" ] && printf "   📄 %s\n" "$f"
      done
      printf "📂 Введите имя файла подсетей: "
      read -r PING_FILE
      [ -f "$PING_FILE" ] || { echo "❌ Файл не найден"; return 1; }
      # Нужно пропинговать заново для отчёта
      do_ping_subnets "$PING_FILE"
      ;;
    *) echo "⚠️ Неверный выбор" ;;
  esac
}

# ══════════════════════════════════════════════════════
# ГЛАВНОЕ МЕНЮ
# ══════════════════════════════════════════════════════
show_menu() {
  clear
  echo ""
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║          🛰️  GLAZ GORA — Сетевой Сканер  🛰️         ║"
  echo "╠══════════════════════════════════════════════════════╣"
  echo "║                                                      ║"
  echo "║   1) 🌐 Проверить доступность по ссылке (VLESS)      ║"
  echo "║   2) 🔍 Найти подсети оператора по ASN               ║"
  echo "║   3) 📡 Определить ASN по IP (авто-детект)           ║"
  echo "║   4) 📶 Пинг подсетей из файла                      ║"
  echo "║   5) 📝 Экспорт отчёта в Obsidian MD                ║"
  echo "║   0) 🚪 Выход                                        ║"
  echo "║                                                      ║"
  echo "╚══════════════════════════════════════════════════════╝"
  echo ""
}

# ══════════════════════════════════════════════════════
# ОСНОВНОЙ ЦИКЛ
# ══════════════════════════════════════════════════════
check_deps

# Если передан аргумент — режим без меню (совместимость)
if [ -n "$1" ]; then
  case "$1" in
    --url)   do_url_scan "$2" ;;
    --asn)   do_asn_lookup "$2" ;;
    --ip)    do_ip_to_asn "$2" ;;
    --ping)  do_ping_subnets "$2" ;;
    http*|ftp*) do_url_scan "$1" ;;  # Обратная совместимость: если передана ссылка
    *)
      echo "Использование:"
      echo "  $0                     — интерактивное меню"
      echo "  $0 --url <ссылка>      — проверка по ссылке"
      echo "  $0 --asn <номер>       — подсети по ASN"
      echo "  $0 --ip <адрес>        — определить ASN по IP"
      echo "  $0 --ping <файл>       — пинг подсетей из файла"
      echo "  $0 <ссылка>            — проверка по ссылке (совместимость)"
      ;;
  esac
  exit 0
fi

# Интерактивный режим
while true; do
  show_menu
  printf "   👉 Выберите действие [0-5]: "
  read -r CHOICE

  case "$CHOICE" in
    1) do_url_scan ;;
    2) do_asn_lookup ;;
    3) do_ip_to_asn ;;
    4) do_ping_subnets ;;
    5) do_export_obsidian ;;
    0)
      echo ""
      echo "👋 До встречи!"
      exit 0
      ;;
    *)
      echo "⚠️ Неверный выбор, попробуйте снова."
      ;;
  esac

  echo ""
  printf "🔄 Нажмите Enter для возврата в меню... "
  read -r _dummy
done