#!/usr/bin/env bash
# Build and install the patched mt76 driver (MT7927 active monitor) on Fedora.
#
#   sudo ./build-install.sh            build, sign (if Secure Boot), install, reload
#   sudo ./build-install.sh --build    build only (into ./build)
#   sudo ./build-install.sh --uninstall
#   sudo ./build-install.sh --reload   unload whatever mt76 is loaded, load the installed one
#
# Env overrides:
#   KVER=<uname -r of target kernel>   default: running kernel
#   MT76_SRC=<path to mt76 dir>        skip fetching kernel sources
#   SIGN_KEY / SIGN_CERT               module signing key + DER cert
#                                      (default: akmods MOK under /etc/pki/akmods)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KVER="${KVER:-$(uname -r)}"
KBUILD="/lib/modules/${KVER}/build"
BUILD_DIR="${HERE}/build/${KVER}"
INSTALL_DIR="/lib/modules/${KVER}/updates/mt7927-active-monitor"
MODPROBE_CONF="/etc/modprobe.d/mt7927-active-monitor.conf"
PATCHES=("${HERE}"/patches/*.patch)
SIGN_KEY="${SIGN_KEY:-/etc/pki/akmods/private/private_key.priv}"
SIGN_CERT="${SIGN_CERT:-/etc/pki/akmods/certs/public_key.der}"
STABLE_GITS=("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
	     "https://github.com/gregkh/linux.git")
MT76_PATH="drivers/net/wireless/mediatek/mt76"
# Unload order: users first, core last.
MODULES_UNLOAD=(mt7925e mt7925u mt7925_common mt7921e mt7921u mt7921s
		mt7921_common mt792x_usb mt792x_lib mt76_connac_lib mt76_usb
		mt76_sdio mt76)

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "run with sudo"; }

check_deps() {
	local missing=()
	for c in git make gcc patch depmod modprobe; do
		command -v "$c" >/dev/null || missing+=("$c")
	done
	[[ -d "$KBUILD" ]] || missing+=("kernel-devel-${KVER}")
	if ((${#missing[@]})); then
		die "missing: ${missing[*]}
  fix: sudo dnf install git make gcc patch kmod kernel-devel-${KVER}"
	fi
}

# 7.3.5-200.fc44.x86_64 -> v7.3.5 ; 7.4.0-... -> v7.4
upstream_tag() {
	local base="${KVER%%-*}"
	local maj min sub
	IFS=. read -r maj min sub <<<"$base"
	if [[ -z "${sub:-}" || "$sub" == 0 ]]; then
		echo "v${maj}.${min}"
	else
		echo "v${maj}.${min}.${sub}"
	fi
}

fetch_source() {
	rm -rf "$BUILD_DIR"
	mkdir -p "$BUILD_DIR"
	if [[ -n "${MT76_SRC:-}" ]]; then
		log "using mt76 source from $MT76_SRC"
		cp -r "$MT76_SRC" "$BUILD_DIR/mt76"
		return
	fi
	local tag; tag="$(upstream_tag)"
	log "fetching ${MT76_PATH} at ${tag} from the stable tree"
	local tmp="$BUILD_DIR/linux"
	local url ok=
	for url in "${STABLE_GITS[@]}"; do
		rm -rf "$tmp"
		if git clone -q --depth 1 --branch "$tag" --filter=blob:none \
			--sparse "$url" "$tmp"; then
			ok=1
			break
		fi
		warn "fetch from $url failed"
	done
	[[ -n $ok ]] ||
		die "could not fetch ${tag}; set MT76_SRC to an mt76 source dir"
	git -C "$tmp" sparse-checkout set "$MT76_PATH"
	cp -r "$tmp/$MT76_PATH" "$BUILD_DIR/mt76"
	rm -rf "$tmp"
}

apply_patches() {
	local p
	for p in "${PATCHES[@]}"; do
		log "applying $(basename "$p")"
		if ! patch -d "$BUILD_DIR/mt76" -p1 --dry-run -s <"$p" >/dev/null; then
			patch -d "$BUILD_DIR/mt76" -p1 --dry-run <"$p" || true
			die "patch does not apply to ${KVER}.
  The patch targets kernels 7.3 and 7.4 (MT7927 with NO_VIRTUAL_MONITOR).
  Send the output above so the patch can be rebased."
		fi
		patch -d "$BUILD_DIR/mt76" -p1 -s <"$p"
	done
}

build() {
	log "building against ${KBUILD}"
	make -C "$KBUILD" M="$BUILD_DIR/mt76" -j"$(nproc)" modules
}

secure_boot_on() {
	command -v mokutil >/dev/null &&
		mokutil --sb-state 2>/dev/null | grep "SecureBoot enabled" >/dev/null
}

sign_modules() {
	if ! secure_boot_on; then
		log "Secure Boot is off, not signing"
		return
	fi
	if [[ ! -r "$SIGN_KEY" || ! -r "$SIGN_CERT" ]]; then
		die "Secure Boot is on but no signing key at
  $SIGN_KEY / $SIGN_CERT
  Create and enroll one (once):
    sudo dnf install akmods mokutil && sudo kmodgenca -a
    sudo mokutil --import $SIGN_CERT
  then reboot, accept the key in the blue MOK screen, and rerun."
	fi
	local signer="$KBUILD/scripts/sign-file" ko
	[[ -x "$signer" ]] || die "missing $signer (kernel-devel)"
	log "signing modules with $SIGN_CERT"
	while IFS= read -r -d '' ko; do
		"$signer" sha256 "$SIGN_KEY" "$SIGN_CERT" "$ko"
	done < <(find "$BUILD_DIR/mt76" -name '*.ko' -print0)
}

unload() {
	local m
	for m in "${MODULES_UNLOAD[@]}"; do
		if [[ -d /sys/module/$m ]]; then
			modprobe -r "$m" || warn "could not unload $m"
		fi
	done
	if [[ -d /sys/module/mt76 ]]; then
		die "mt76 is still loaded (in use?). Check: lsmod | grep mt7"
	fi
}

install_modules() {
	log "installing into ${INSTALL_DIR}"
	rm -rf "$INSTALL_DIR"
	mkdir -p "$INSTALL_DIR"
	(cd "$BUILD_DIR/mt76" && find . -name '*.ko' -exec cp --parents {} "$INSTALL_DIR" \;)
	depmod -a "$KVER"

	cat >"$MODPROBE_CONF" <<-'EOF'
	# Installed by MonitorModeBridge Driver/mt7927/build-install.sh
	options mt792x_lib allow_active_monitor=1
	# Set to 0 to test HW ACKs without firmware sniffer mode (see README)
	options mt7925_common monitor_sniffer=1
	EOF

	if [[ "$KVER" == "$(uname -r)" ]]; then
		log "reloading driver"
		unload
		modprobe mt7925e
		sleep 2
		verify
	else
		log "installed for ${KVER}; reboot into it to use"
	fi
}

verify() {
	local f=/sys/module/mt792x_lib/parameters/allow_active_monitor
	modinfo -n mt7925e
	if [[ -r $f ]]; then
		echo "allow_active_monitor=$(cat "$f")"
	else
		warn "patched mt792x_lib not loaded (no allow_active_monitor param)"
	fi
	if command -v iw >/dev/null; then
		if iw list 2>/dev/null | grep -i "active monitor" >/dev/null; then
			log "OK: driver now advertises active monitor"
		else
			warn "active monitor still not advertised; run test-active-monitor.sh info"
		fi
	fi
}

uninstall() {
	log "removing ${INSTALL_DIR} and ${MODPROBE_CONF}"
	rm -rf "$INSTALL_DIR" "$MODPROBE_CONF"
	depmod -a "$KVER"
	if [[ "$KVER" == "$(uname -r)" ]]; then
		unload
		modprobe mt7925e || true
	fi
	log "stock driver restored"
}

case "${1:-}" in
--reload)
	need_root; unload; modprobe mt7925e; sleep 2; verify ;;
--uninstall)
	need_root; uninstall ;;
--build)
	check_deps; fetch_source; apply_patches; build
	log "modules in $BUILD_DIR/mt76" ;;
"")
	need_root; check_deps; fetch_source; apply_patches; build
	sign_modules; install_modules ;;
*)
	sed -n '2,15p' "$0"; exit 1 ;;
esac
