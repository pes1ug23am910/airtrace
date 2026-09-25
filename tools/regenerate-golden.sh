#!/bin/sh
# Regenerate the independent oracle; normal builds only read committed TSVs.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
for name in wpa-Induction Network_Join_Nokia_Mobile; do
    tshark -n -r "tests/fixtures/$name.pcap" \
      -o wlan.enable_decryption:FALSE -T fields \
      -E header=y -E separator=/t -E quote=n -E occurrence=f \
      -e frame.number -e frame.time_epoch \
      -e wlan.fc.type -e wlan.fc.subtype \
      -e radiotap.dbm_antsignal -e radiotap.channel.freq \
      -e wlan.ds.current_channel -e wlan.ra -e wlan.ta -e wlan.bssid \
      -e wlan.ssid -e wlan.seq -e wlan.fc.retry -e wlan.fc.protected \
      -e wlan.fixed.status_code -e wlan.fixed.reason_code \
      -e wlan_rsna_eapol.keydes.msgnr -e wlan.fc.tods -e wlan.fc.fromds \
      -e wlan.da -e wlan.sa -e wlan.fc.version > "tests/fixtures/$name.tsv"
done
tshark --version | head -n 1 > tests/fixtures/TSHARK_VERSION.txt
