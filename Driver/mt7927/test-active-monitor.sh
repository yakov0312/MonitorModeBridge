#!/usr/bin/env bash
# Test active monitor mode on the MT7927 with the patched driver.
#
#   sudo ./test-active-monitor.sh info
#   sudo ./test-active-monitor.sh all              full comparison, uses the AP
#                                                  you are connected to now
#   sudo ./test-active-monitor.sh all <freq> <bssid>
#
# Single steps:
#   setup <freq> [active|passive]   create mon0 on <freq> MHz (e.g. 2437, 5180)
#   rx [seconds]                    check RX keeps flowing on mon0 (default 120)
#   ack <bssid>                     does the card ACK frames to mon0's MAC?
#   teardown                        delete mon0, give the card back to NetworkManager
#
# `all` writes report-<date>.txt next to this script.  Send that file back.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MON=mon0
# Locally administered MAC for the monitor vif; the ACK test targets it.
MON_MAC="${MON_MAC:-02:4d:4d:42:00:01}"
SNIFFER_PARAM=/sys/module/mt7925_common/parameters/monitor_sniffer

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run with sudo"
command -v iw >/dev/null || die "install iw: sudo dnf install iw"

find_phy() {
	local p drv
	for p in /sys/class/ieee80211/phy*; do
		drv="$(basename "$(readlink -f "$p/device/driver")" 2>/dev/null)"
		if [[ "$drv" == mt7925e ]]; then
			basename "$p"
			return 0
		fi
	done
	return 1
}

find_wlan() {
	local phy="$1" n
	for n in /sys/class/ieee80211/"$phy"/device/net/*; do
		[[ -e "$n" ]] || continue
		n="$(basename "$n")"
		[[ "$n" == "$MON" ]] && continue
		echo "$n"
		return 0
	done
	return 1
}

PHY="$(find_phy)" || die "no mt7925e (MT7927) phy found; is the driver loaded?"

cmd_info() {
	echo "### system"
	uname -r
	grep -E '^(NAME|VERSION)=' /etc/os-release
	echo "### pci"
	lspci -nnk -d 14c3: 2>/dev/null || lspci -nnk | grep -iA3 network
	echo "### modules"
	for m in mt7925e mt7925_common mt792x_lib mt76; do
		printf '%-15s %s\n' "$m" "$(modinfo -n "$m" 2>/dev/null)"
	done
	echo "allow_active_monitor=$(cat /sys/module/mt792x_lib/parameters/allow_active_monitor 2>/dev/null || echo 'n/a (stock driver)')"
	echo "monitor_sniffer=$(cat "$SNIFFER_PARAM" 2>/dev/null || echo 'n/a (stock driver)')"
	echo "### firmware"
	dmesg 2>/dev/null | grep -iE 'mt79|mt7925|mt6639' | grep -iE 'firmware|version|build' | tail -5
	echo "### phy $PHY"
	if iw phy "$PHY" info | grep -qi "active monitor"; then
		echo "active monitor: ADVERTISED"
	else
		echo "active monitor: not advertised"
	fi
	iw phy "$PHY" info | sed -n '/Supported interface modes/,/^\t[^\t]/p' | head -12
}

cmd_teardown() {
	iw dev "$MON" del 2>/dev/null || true
	local w
	if w="$(find_wlan "$PHY")"; then
		ip link set "$w" up 2>/dev/null || true
		command -v nmcli >/dev/null && nmcli device set "$w" managed yes 2>/dev/null
	fi
	return 0
}

# setup <freq> [active|passive]
cmd_setup() {
	local freq="${1:?freq in MHz, e.g. 2437 or 5180}" mode="${2:-active}" w flags
	cmd_teardown
	if w="$(find_wlan "$PHY")"; then
		log "taking $w away from NetworkManager"
		command -v nmcli >/dev/null && nmcli device set "$w" managed no 2>/dev/null
		ip link set "$w" down
	fi
	flags="control otherbss"
	[[ "$mode" == active ]] && flags="active $flags"
	log "creating $MON on $PHY: type monitor flags $flags"
	# shellcheck disable=SC2086
	if ! iw phy "$PHY" interface add "$MON" type monitor flags $flags; then
		warn "interface add failed (active monitor not advertised?)"
		return 1
	fi
	ip link set "$MON" address "$MON_MAC" || warn "could not set MAC $MON_MAC"
	ip link set "$MON" up || { warn "could not bring $MON up"; return 1; }
	iw dev "$MON" set freq "$freq" || { warn "could not set freq $freq"; return 1; }
	iw dev "$MON" info | grep -E 'type|addr|channel'
}

# rx [seconds]: sample rx_packets every 5s; a 0-packet interval is a stall.
cmd_rx() {
	local secs="${1:-120}" stat="/sys/class/net/$MON/statistics/rx_packets"
	[[ -r $stat ]] || { warn "$MON does not exist"; return 1; }
	local prev cur t=0 stalls=0 total=0 dmesg_before
	dmesg_before="$(dmesg 2>/dev/null | wc -l)"
	prev="$(cat "$stat")"
	log "watching RX on $MON for ${secs}s"
	while ((t < secs)); do
		sleep 5
		t=$((t + 5))
		cur="$(cat "$stat")"
		printf '  t=%3ds  +%d frames\n' "$t" $((cur - prev))
		((cur == prev)) && stalls=$((stalls + 1))
		total=$((total + cur - prev))
		prev=$cur
	done
	echo "RX total: $total frames, stalled intervals: $stalls/$((secs / 5))"
	dmesg 2>/dev/null | tail -n +"$((dmesg_before + 1))" | grep -iE 'mt79|mt76|timeout|reset' | tail -10
	if ((total == 0)); then
		echo "RX RESULT: DEAD"
		return 1
	elif ((stalls > 0)); then
		echo "RX RESULT: STALLS"
		return 3
	fi
	echo "RX RESULT: OK"
}

cmd_ack() {
	local bssid="${1:?bssid of your AP}"
	python3 "$HERE/ack_test.py" "$MON" "$bssid" --src "$MON_MAC"
}

set_sniffer() {
	if [[ -w $SNIFFER_PARAM ]]; then
		echo "$1" >"$SNIFFER_PARAM"
	else
		warn "monitor_sniffer param missing (stock driver?)"
	fi
}

run_case() {
	local name="$1" mode="$2" sniffer="$3" freq="$4" bssid="$5"
	echo
	echo "################ CASE: $name (mode=$mode monitor_sniffer=$sniffer)"
	set_sniffer "$sniffer"
	if cmd_setup "$freq" "$mode"; then
		cmd_rx 60
		cmd_ack "$bssid"
	else
		echo "SETUP FAILED"
	fi
	cmd_teardown
	sleep 3
}

# all [freq bssid]
cmd_all() {
	local freq="${1:-}" bssid="${2:-}" w link
	if [[ -z "$freq" || -z "$bssid" ]]; then
		w="$(find_wlan "$PHY")" || die "no managed interface; pass <freq> <bssid>"
		link="$(iw dev "$w" link)"
		bssid="$(awk '/^Connected to/ {print $3}' <<<"$link")"
		freq="$(awk '/freq:/ {print int($2)}' <<<"$link")"
		[[ -n "$bssid" && -n "$freq" ]] ||
			die "$w is not connected; connect to your AP first or pass <freq> <bssid>"
	fi
	local report
	report="$HERE/report-$(date +%Y%m%d-%H%M%S).txt"
	log "AP $bssid on $freq MHz; writing $report"
	{
		echo "MonitorModeBridge MT7927 active monitor report"
		date
		echo "AP: $bssid  freq: $freq"
		cmd_info
		run_case "baseline passive monitor" passive 1 "$freq" "$bssid"
		run_case "active monitor, sniffer mode" active 1 "$freq" "$bssid"
		run_case "active monitor, no sniffer mode" active 0 "$freq" "$bssid"
		set_sniffer 1
		echo
		echo "### dmesg tail"
		dmesg 2>/dev/null | grep -iE 'mt79|mt76' | tail -30
	} 2>&1 | tee "$report"
	log "done. Send back: $report"
}

case "${1:-}" in
info)     cmd_info ;;
setup)    shift; cmd_setup "$@" ;;
rx)       shift; cmd_rx "$@" ;;
ack)      shift; cmd_ack "$@" ;;
teardown) cmd_teardown ;;
all)      shift; cmd_all "$@" ;;
*)        sed -n '2,16p' "$0"; exit 1 ;;
esac
