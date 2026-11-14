#!/usr/bin/env bash
# Accuracy run on Brim's public sample data: download (pinned, SHA-256 checked), make reference
# Zeek logs with a separate Zeek, run VulnScope in its container, compare every number.
#
#   scripts/accuracy/run.sh DATA_DIR WORK_DIR
#
# IMAGE (default vulnscope-max:ci), ZEEK_IMAGE and SURICATA_IMAGE can be overridden.
# Nothing downloaded here is committed or put in the image; it lives in DATA_DIR only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="$(mkdir -p "$1" && cd "$1" && pwd)"
WORK="$(mkdir -p "$2" && cd "$2" && pwd)"
IMAGE="${IMAGE:-vulnscope-max:ci}"
ZEEK_IMAGE="${ZEEK_IMAGE:-zeek/zeek:9.0.1}"
SURICATA_IMAGE="${SURICATA_IMAGE:-jasonish/suricata:8.0.8}"

python3 "$HERE/fetch.py" "$DATA"
mkdir -p "$WORK/zeek" "$WORK/runs" "$WORK/inputs"
chmod 777 "$WORK/runs"                     # the VulnScope container runs as uid 1000

analyze() {                                 # analyze FOLDER NAME
  docker run --rm -v "$1:/data/$2:ro" -v "$WORK/runs:/runs" "$IMAGE" \
    analyze "/data/$2" -o "/runs/$2" > "$WORK/runs/$2.log" 2>&1 \
    || { echo "VulnScope failed on $2:"; tail -20 "$WORK/runs/$2.log"; return 1; }
}

# PCAPs: reference logs from a separate Zeek, then VulnScope (which runs its own Zeek inside)
for d in zui_sample_pcap zui_sample_pcapng brimcap_alerts_pcap brimcap_in_pcap brimcap_ng_pcap \
         brimcap_extra_pcapng brimcap_oneflow_pcap brimcap_loopback_pcap brimcap_pings_pcapnano; do
  f="$(ls "$DATA/$d")"
  mkdir -p "$WORK/zeek/$d"
  docker run --rm -v "$DATA/$d:/in:ro" -v "$WORK/zeek/$d:/out" -w /out "$ZEEK_IMAGE" \
    zeek -C -r "/in/$f" local > "$WORK/zeek/$d.out" 2>&1
  analyze "$DATA/$d" "$d"
done

# Logs as Brim publishes them
for d in wrccdc_tsv wrccdc_json zui_export; do
  analyze "$DATA/$d" "$d"
done

# Suricata on alerts.pcap with the built-in event rules and the harmless test rules
mkdir -p "$WORK/runs/_eve"
docker run --rm --entrypoint sh -v "$HERE/suricata.rules:/r/local.rules:ro" "$SURICATA_IMAGE" \
  -c 'cat /usr/share/suricata/rules/*.rules /r/local.rules' > "$WORK/all.rules"
docker run --rm -v "$DATA/brimcap_alerts_pcap:/in:ro" -v "$WORK/all.rules:/r/all.rules:ro" \
  -v "$WORK/runs/_eve:/out" --entrypoint suricata "$SURICATA_IMAGE" \
  -k none -r /in/alerts.pcap -S /r/all.rules -l /out \
  --set 'vars.address-groups.HOME_NET=[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]' > "$WORK/suricata.out" 2>&1
test -s "$WORK/runs/_eve/eve.json"
mkdir -p "$WORK/inputs/suricata_with_zeek" "$WORK/inputs/suricata_only" "$WORK/zeek/suricata_with_zeek"
cp "$DATA/brimcap_alerts_pcap/alerts.pcap" "$WORK/runs/_eve/eve.json" "$WORK/inputs/suricata_with_zeek/"
cp "$WORK/runs/_eve/eve.json" "$WORK/inputs/suricata_only/"
cp "$WORK/zeek/brimcap_alerts_pcap/"*.log "$WORK/runs/_eve/eve.json" "$WORK/zeek/suricata_with_zeek/"
analyze "$WORK/inputs/suricata_with_zeek" suricata_with_zeek
analyze "$WORK/inputs/suricata_only" suricata_only

python3 "$HERE/check.py" "$DATA" "$WORK/runs" "$WORK/zeek"
