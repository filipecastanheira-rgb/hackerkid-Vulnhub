#!/bin/bash
# Brute-force do parâmetro page_no em index.php, comparando o tamanho da
# resposta para identificar valores que devolvem conteúdo diferente do
# comportamento por defeito.
#
# Uso: ./page_no_bruteforce.sh <IP_ALVO> [MAX]
# Exemplo: ./page_no_bruteforce.sh 192.168.1.138 500

TARGET="${1:?Uso: $0 <IP_ALVO> [MAX]}"
MAX="${2:-500}"

echo "[*] A determinar o tamanho de resposta 'normal' (page_no=1)..."
BASELINE=$(curl -s -o /dev/null -w "%{size_download}" "http://${TARGET}/index.php?page_no=1")
echo "[*] Tamanho de referência: ${BASELINE} bytes"
echo "[*] A testar page_no=1 até page_no=${MAX}..."

for i in $(seq 1 "$MAX"); do
    size=$(curl -s -o /dev/null -w "%{size_download}" "http://${TARGET}/index.php?page_no=${i}")
    if [ "$size" != "$BASELINE" ]; then
        echo "[+] page_no=${i} -> ${size} bytes (diferente do baseline!)"
    fi
done

echo "[*] Concluído."
