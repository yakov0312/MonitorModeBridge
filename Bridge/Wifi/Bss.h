// C++ replacement for libwifi: what an AP announces about itself
// (libwifi_bss), read from a beacon or probe response.

#pragma once

#include "Common.h"
#include "Frame.h"
#include "Tags.h"
#include "Wpa.h"

namespace Wifi
{

constexpr size_t MAX_SSID_LENGTH = 32;

struct Bss
{
	MacAddress receiver{};
	MacAddress transmitter{};
	MacAddress bssid{};
	std::string ssid;
	bool hidden = false;      // empty or all-zero SSID
	uint8_t channel = 0;      // DS Parameter Set / HT Operation primary channel
	bool wps = false;
	uint64_t encryptionInfo = 0; // Wpa::Flag bits
	// (signal strength: frame.signal(), only decoded when you ask for it)
	std::optional<Wpa::RsnInfo> rsn;
	std::optional<Wpa::WpaInfo> wpa;

	// Fixed parameters
	uint64_t timestamp = 0;
	uint16_t beaconInterval = 0;
	uint16_t capabilities = 0;

	Tags tags;

	// Beacon or probe response (libwifi_parse_beacon/probe_resp)
	static std::optional<Bss> parse(const Frame& frame);

	[[nodiscard]] bool isOpen() const { return encryptionInfo == 0; }
	[[nodiscard]] bool has(uint64_t wpaFlag) const { return (encryptionInfo & wpaFlag) != 0; }
	// Supported Rates followed by Extended Supported Rates
	[[nodiscard]] std::vector<uint8_t> supportedRates() const;

	[[nodiscard]] std::string securityTypes() const { return Wpa::securityTypes(encryptionInfo); }
	[[nodiscard]] std::string groupCiphers() const { return Wpa::groupCiphers(encryptionInfo); }
	[[nodiscard]] std::string pairwiseCiphers() const { return Wpa::pairwiseCiphers(encryptionInfo); }
	[[nodiscard]] std::string akmSuites() const { return Wpa::akmSuites(encryptionInfo); }

	// Fills ssid/hidden/channel/wps/encryptionInfo/rsn/wpa from tags.
	// privacy is the capability bit (WEP unless an RSN/WPA tag says more).
	void readTags(Tags source, bool privacy);
};

// Fixed parameters shared by beacons and probe responses:
// timestamp (8) + interval (2) + capabilities (2)
struct BssFixedParameters
{
	static constexpr size_t LENGTH = 12;

	uint64_t timestamp = 0;
	uint16_t interval = DEFAULT_BEACON_INTERVAL;
	uint16_t capabilities = DEFAULT_AP_CAPABILITIES;

	void write(ByteWriter& w) const;
	static BssFixedParameters read(ByteReader& r);
};

} // namespace Wifi
