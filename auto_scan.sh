#!/bin/sh
# vless_scan.sh — Загрузка по ссылке → Ping → Whois (с умным фильтром RIPE/ARIN)

URL="$1"
if [[ -z "$URL" ]]; then
  read -p "🌐 Введите прямую ссылку на файл с ключами: " URL
fi
[[ -z "$URL" ]] && { echo "❌ Ссылка не указана."; exit 1; }

for cmd in curl grep ping whois awk sort cut; do
  command -v "$cmd" &>/dev/null || { echo "❌ Установите: $cmd"; exit 1; }
done

TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT
OUT_CSV="ip_whois_results.csv"

# ═══════════════════════════════════════════════════════
echo "🔐 ШАГ 1: Включите VPN для загрузки ключей"
echo "══════════════════════════════════════════════════════"
read -p "   ✅ VPN включён? Нажмите Enter... "

echo "📥 Загружаю: $URL"
if ! curl -sL --max-time 15 --fail "$URL" -o "$TMP_DIR/keys.txt" 2>/dev/null; then
  echo "❌ Ошибка загрузки. Проверьте ссылку и подключение."; exit 1
fi

# Извлечение уникальных IP
grep -oE '@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMP_DIR/keys.txt" | cut -d'@' -f2 | sort -u > "$TMP_DIR/all_ips.txt"
TOTAL=$(wc -l < "$TMP_DIR/all_ips.txt")
echo "   📦 Найдено уникальных IP: $TOTAL"
[[ "$TOTAL" -eq 0 ]] && { echo "❌ IP не найдены в подписке."; exit 1; }

# ═══════════════════════════════════════════════════════
echo ""
echo "🔓 ШАГ 2: Выключите VPN для точного пинга"
echo "══════════════════════════════════════════════════════"
read -p "   ✅ VPN выключен? Нажмите Enter... "

echo "📡 Пингую хосты (таймаут 2с)..."
> "$TMP_DIR/reachable.txt"
COUNT=0
while IFS= read -r ip; do
  COUNT=$((COUNT + 1))
  printf "\r   ⏳ [%3d/%3d] %-15s" "$COUNT" "$TOTAL" "$ip"
  if ping -c 1 -W 2 "$ip" &>/dev/null; then
    echo "$ip" >> "$TMP_DIR/reachable.txt"
  fi
done < "$TMP_DIR/all_ips.txt"
echo ""
REACH=$(wc -l < "$TMP_DIR/reachable.txt")
echo "   ✅ Доступных: $REACH из $TOTAL"
[[ "$REACH" -eq 0 ]] && { echo "⚠️ Ни один хост не ответил. Завершаю."; exit 0; }

# ═══════════════════════════════════════════════════════
echo ""
echo "🔐 ШАГ 3: Включите VPN для whois-запросов"
echo "══════════════════════════════════════════════════════"
read -p "   ✅ VPN включён? Нажмите Enter для запуска whois... "

echo "IP;ORG;COUNTRY;ASN;SUBNET" > "$OUT_CSV"
COUNT=0
while IFS= read -r ip; do
  COUNT=$((COUNT + 1))
  printf "\r   ⏳ [%3d/%3d] %s" "$COUNT" "$REACH" "$ip"

  RAW=$(timeout 10 whois -H "$ip" 2>/dev/null | tr -d '\r')

  if [[ -z "$RAW" ]]; then
    echo "$ip;Timeout;-;-;${ip%.*}.0/24" >> "$OUT_CSV"
    continue
  fi

  # === Умный парсинг (фильтр регистраторов) ===
  REGEX_IGNORE='RIPE Network Coordination Centre|^RIPE$|ARIN|APNIC|IANA|RIPE NCC|Legacy|ERX'

  # 1. Ищем org-name, пропуская RIPE/ARIN/APNIC. Берем последний элемент (tail -n 1)
  ORG=$(echo "$RAW" | grep -iE '^org-name:|^organisation:|^orgname:|^Organization:' | sed 's/^[^:]*:[[:space:]]*//' | grep -ivE "$REGEX_IGNORE" | tail -n 1 | tr -d '\n')

  # 2. Если только регистратор — пробуем netname
  if [[ -z "$ORG" ]]; then
    NETNAME=$(echo "$RAW" | grep -iE '^netname:|^NetName:' | sed 's/^[^:]*:[[:space:]]*//' | grep -ivE "$REGEX_IGNORE" | tail -n 1 | tr -d '\n')
    [[ -n "$NETNAME" ]] && ORG="$NETNAME"
  fi

  # 3. Если всё ещё пусто — берём descr (описание сети/провайдера)
  if [[ -z "$ORG" ]]; then
    DESCR=$(echo "$RAW" | grep -iE '^descr:|^Description:' | sed 's/^[^:]*:[[:space:]]*//' | grep -ivE "$REGEX_IGNORE" | tail -n 1 | tr -d '\n')
    [[ -n "$DESCR" ]] && ORG="$DESCR"
  fi

  # 4. Если вообще ничего нет — ставим понятную пометку
  [[ -z "$ORG" ]] && ORG="Legacy/Unassigned"

  ASN=$(echo "$RAW" | grep -iE '^origin:|^aut-num:|^OriginAS:' | grep -oiE 'AS[0-9]+' | tail -n 1 | tr -d '\n')
  [[ -z "$ASN" ]] && ASN="-"

  CC=$(echo "$RAW" | grep -iE '^country:' | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\n' | tr '[:lower:]' '[:upper:]')
  [[ -z "$CC" ]] && CC="Unknown"

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
  printf "%-16s | %-25s | %-6s | %-10s | %s\n" "$ip" "${org:0:25}" "$cc" "$asn" "$subnet"
done
printf "%s\n" "──────────────────────────────────────────────────────────────────────────────"

echo ""
echo "📈 Топ-10 провайдеров:"
tail -n +2 "$OUT_CSV" | cut -d';' -f2 | sort | uniq -c | sort -rn | head -10 | while read -r cnt name; do
  printf "   • %3d IP — %s\n" "$cnt" "$name"
done