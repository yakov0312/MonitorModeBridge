# Wifi: C++ replacement for libwifi

`#include <Wifi/Wifi.h>`. Everything is in `namespace Wifi`. All types are values that own their memory, so there's nothing to `free`.

| Class | What |
|---|---|
| `Frame` | received frame (radiotap skipped, FCS cut off), replaces `libwifi_frame` |
| `Radiotap` | radiotap parse (multi-word / per-antenna) and build |
| `Tags` | tagged parameters: add / set / remove / find / serialize |
| `Bss` | what a beacon or probe response says, replaces `libwifi_bss` |
| `Beacon` | beacon frames |
| `Probe` | `Probe::Request`, `Probe::Response` |
| `Auth` | authentication, and `Auth::Deauth` (deauth + disassoc) |
| `Assoc` | `Assoc::Request`, `Assoc::Response` (both also do reassociation) |
| `Wpa` | RSN/WPA elements, security flags, EAPOL-Key parse/build, handshake message |

Every frame class has `create(...)` (same defaults as libwifi), `build()` → `std::vector<uint8_t>`, `length()` and `static parse(const Frame&)` → `std::optional`.

## libwifi → Wifi

| libwifi | Wifi |
|---|---|
| `libwifi_get_wifi_frame(&f, data, len, 1)` | `auto f = Frame::parse({data, len})` |
| `libwifi_free_*(...)` | nothing |
| `f.frame_control.type == TYPE_MANAGEMENT && subtype == SUBTYPE_PROBE_RESP` | `f.is(ManagementSubtype::ProbeResp)` |
| `f.frame_control.flags.retry` | `f.isRetry()` |
| `f.header.mgmt_unordered.addr2` | `f.transmitter()` / `f.header().addr2` |
| `f.body`, `f.len - f.header_len` | `f.body()` (a span) |
| `libwifi_create_probe_req` + `get_length` + `dump` | `Probe::Request::create(BROADCAST, mac, BROADCAST, ssid, 1).build()` |
| `libwifi_parse_probe_resp(&bss, &f)` | `auto bss = Probe::Response::parseBss(f)` |
| `libwifi_parse_beacon(&bss, &f)` | `auto bss = Beacon::parseBss(f)` |
| `bss.encryption_info & WPA2` | `bss->has(Wpa::Flag::Wpa2)` |
| `LIBWIFI_AKM_SUITE_PSK`, `LIBWIFI_PAIRWISE_CIPHER_SUITE_CCMP128`, … | `Wpa::Flag::AkmPsk`, `Wpa::Flag::PairwiseCcmp128`, … (same bits) |
| `bss.rsn_info.group_cipher_suite.suite_type` | `bss->rsn->groupCipher.type` |
| tag iterator loop looking for `TAG_SUPP_RATES` | `bss->tags.find(TagNumber::SupportedRates)->data` |
| `libwifi_create_auth(&a, ap, me, ap, AUTH_OPEN, 1, 0)` | `Auth::create(ap, me, ap).build()` |
| `(libwifi_auth_fixed_parameters*)f.body` → `status_code` | `Auth::parse(f)->status` / `->succeeded()` |
| `libwifi_create_assoc_req` + `libwifi_quick_add_tag` | `auto r = Assoc::Request::create(...); r.tags.add(TagNumber::SupportedRates, rates);` |
| `(libwifi_assoc_resp_fixed_parameters*)f.body` | `Assoc::Response::parse(f)` → `status`, `aid()` |
| `libwifi_check_wpa_handshake(&f) > 0` | `Wpa::isEapol(f)` |
| `libwifi_get_wpa_data` + `libwifi_check_wpa_message` | `auto key = Wpa::EapolKey::parse(f); key->message()` |
| `HANDSHAKE_M1` … `HANDSHAKE_M4` | `Wpa::HandshakeMessage::M1` … `M4` (same values) |
| `wpaData.key_info.nonce / replay_counter / key_data` | `key->nonce / replayCounter / keyData` (host order) |
| `libwifi_create_radiotap(&info, buf)` (flags + channel) | `Radiotap::buildForChannel(channelToFrequency(ch))` |
| `RSN_WPA2` array + index patching | `Wpa::RsnInfo::create(group, pairwise, akm).build()` |
| hand-built `EapolFrame` struct | `Wpa::EapolKey` + `buildDataFrame(bssid, me, seq)`, MIC at `EapolKey::micOffset()` |

`toMac(const uint8_t*)` turns the existing raw MAC pointers into a `MacAddress`.

## Differences from libwifi

These are fixes; none of them change bytes on the air:

- Zero-length tags (wildcard SSID) and the last tag of a frame are no longer dropped.
- Data frame headers include Address 4 (WDS) and HT Control when present.
- Radiotap: extended presence words, per-antenna namespaces, and correct MCS and timestamp offsets.
- WPA1 vendor tags no longer wipe AKM flags set by an RSN tag.
- The handshake message is decided from the key info bits, so it also works for descriptor versions 0/1/3, not only `0x008A`/`0x010A`/`0x13CA`/`0x030A`.
- New WPA3 AKMs: `SaeExtKey` (24) and `FtSaeExtKey` (25), which WiFi 7 routers use. Their flags are `Wpa::Flag::AkmSaeExtKey` and `AkmFtSaeExtKey`.

## Tests

```bash
cmake -B build -DMMB_BUILD_TESTS=ON && cmake --build build
./build/WifiTests WifiConnectionSniff.pcapng
```

These tests build every frame with both libraries and compare the bytes. They also parse every frame of the capture with both and compare the results.
