# MT7927 active monitor mode (Fedora)

Experimental driver patch and test tools to get **active monitor mode** on the
MediaTek **MT7927 (Filogic 380)** WiFi 7 chip, for example the onboard WiFi of
the MSI MAG B850 Tomahawk MAX WiFi II.

In active monitor mode the card **ACKs unicast frames addressed to the monitor
interface's MAC**. MonitorModeBridge needs this so the AP stops retransmitting
frames sent to the bridge, instead of relying on ACKs sent from userspace.

> Status: **works on hardware** (MSI MAG B850 Tomahawk MAX WiFi II, Fedora 44,
> kernel 7.3.4-200.fc44, firmware build 20260414). See [Results](#results).

## Results

Tested against a 2.4 GHz AP (channel 5, 2432 MHz), 20 auth exchanges per check:

| Case | RX (60 s) | ACK to monitor MAC | Control (unowned MAC) |
|---|---|---|---|
| passive monitor, sniffer mode | OK, ~1200 frames, no stalls | **ACKED**: 1.00 copies, 0 retries | NOT ACKED: 2.7 copies, 43 retries |
| active monitor, sniffer mode | OK, ~1170 frames, no stalls | **ACKED**: 1.00 copies, 0 retries | NOT ACKED: 3.0 copies, 51 retries |
| active monitor, `monitor_sniffer=0` | **DEAD** (only own-MAC frames) | ACKED | no replies received |

* The upstream reason for the ban ("RX stops in active monitor") does not
  happen on MT7927 with this patch.
* The hardware ACKs unicast frames to the monitor vif MAC, in passive mode
  too: every monitor vif is a real OMAC on MT7927.
* Firmware sniffer mode must stay on (`monitor_sniffer=1`, the default).
  Without it the RX filter behaves like a station and only passes frames
  for the vif's own MAC.

## Findings

| | |
|---|---|
| Chip | MediaTek MT7927 / MT6639, PCI ID `14c3:7927` |
| Driver | `mt7925e` (mt76 family). MT7927 support landed upstream in 2026 |
| Firmware | `linux-firmware`: `mediatek/mt7927/WIFI_RAM_CODE_MT6639_2_1.bin`, `WIFI_MT6639_PATCH_MCU_2_1_hdr.bin` |
| Active monitor | **not advertised.** Upstream commit `9de65849` ("mt792x: do not advertise active monitor", July 2026) sets `phy->mt76->no_active_monitor = true` in `mt792x_core.c`, because mt7921/mt7925 firmware stops RX in active monitor mode |

Without `NL80211_FEATURE_ACTIVE_MONITOR`, cfg80211 rejects
`iw ... type monitor flags active` with `-EOPNOTSUPP` before the driver ever sees it.

### Why it may still work on MT7927

Upstream commit `aa5a2b4f` makes MT7927 use `NO_VIRTUAL_MONITOR`. Every monitor
interface is then a real vif with its own OMAC (own MAC entry) in firmware,
whether it is active or not. The "active" flag hardly changes the driver's
behaviour, so the ban was probably inherited from the older chips rather than
measured on MT7927.

The same code also showed two real bugs for monitor mode on MT7927:

1. **Power save never turns off.** Runtime PM and deep sleep are only disabled
   when `IEEE80211_CONF_MONITOR` is set, but mac80211 never sets it with
   `NO_VIRTUAL_MONITOR`. The chip can doze while monitoring, and RX stalls.
2. **Sniffer mode is only turned on in `change_chanctx`**, not when a monitor
   vif first gets a channel, and it is never turned off.

## The patch

`patches/0001-wifi-mt76-mt7927-experimental-active-monitor-support.patch`

| Change | Effect |
|---|---|
| `mt792x_lib.allow_active_monitor=1` | advertise active monitor (MT7927 only, off by default) |
| `monitor_vifs` counter | keeps runtime PM and deep sleep off while any monitor vif exists |
| sniffer on at `assign_vif_chanctx`, off at last monitor removal (per band) | monitoring works right after `set freq` |
| `mt7925_common.monitor_sniffer=0` (runtime-writable) | **experiment:** skip firmware sniffer mode and program the channel through the normal BSS path, to see whether the hardware then ACKs |

## Install (Fedora)

```bash
sudo dnf install git make gcc patch kmod iw python3 kernel-devel-$(uname -r)
cd Driver/mt7927
sudo ./build-install.sh
```

The script:
1. fetches `drivers/net/wireless/mediatek/mt76` for your running kernel from the stable git tree (or uses `MT76_SRC=`),
2. applies the patch and builds it against `/lib/modules/$(uname -r)/build`,
3. signs the modules if Secure Boot is on (akmods MOK key; it prints how to create and enroll one if missing),
4. installs into `/lib/modules/$(uname -r)/updates/mt7927-active-monitor/`,
5. writes `/etc/modprobe.d/mt7927-active-monitor.conf` and reloads the driver.

The modules are tied to one kernel build, so rerun after every kernel update.
To undo: `sudo ./build-install.sh --uninstall`.

## Test

Connect to your own AP normally first, then run:

```bash
sudo ./test-active-monitor.sh info    # versions, firmware, "active monitor: ADVERTISED"?
sudo ./test-active-monitor.sh all     # ~4 minutes, writes report-<date>.txt
```

`all` runs three cases on your AP's channel:

| Case | Answers |
|---|---|
| passive monitor | baseline: RX works, and the card should **not** ACK |
| active monitor, sniffer mode | does RX survive? does the card ACK? |
| active monitor, no sniffer mode | does the card ACK when it's not in firmware sniffer mode? |

Each case runs:
* **RX check:** counts received frames every 5 s for 60 s. `OK`, `STALLS` or `DEAD`.
* **ACK check** (`ack_test.py`): injects an open auth request to the AP from
  the monitor MAC, then counts the AP's replies.
  * `ACKED`: one copy per reply, Retry bit clear.
  * `NOT ACKED`: the AP retransmits with the Retry bit set.

While a test runs the card is taken from NetworkManager, so you're offline
until it finishes. `teardown` (run automatically at the end) gives it back.

## What the results mean / next steps

| Result | Next step |
|---|---|
| active + sniffer: RX OK, ACKED | done: set `allow_active_monitor=1` and use it in MonitorModeBridge |
| RX OK but NOT ACKED with sniffer, ACKED without | default `monitor_sniffer=0` for active vifs only (needs the active flag passed to the driver) |
| NOT ACKED in every case | firmware doesn't ACK for a monitor OMAC. Next try registering the vif as `CONNECTION_INFRA_STA` with the spoofed MAC plus the RX filter in promiscuous mode, or keep the userspace ACKs |
| RX DEAD/STALLS | compare with `iw dev mon0 set power_save off` and the debugfs `runtime-pm` / `deep-sleep` knobs; send `dmesg` |
