// C++ replacement for libwifi: beacon frames.

#pragma once

#include "Bss.h"

namespace Wifi
{

class Beacon
{
public:
	MacHeader header = MacHeader::management(ManagementSubtype::Beacon, BROADCAST, {}, {});
	BssFixedParameters fixed;
	Tags tags;

	// libwifi_create_beacon: SSID + DS Parameter Set tags, default interval
	// (100 TU), ESS capability, current time as the timestamp
	static Beacon create(const MacAddress& receiver, const MacAddress& transmitter,
		const MacAddress& bssid, std::string_view ssid, uint8_t channel);

	void setSsid(std::string_view ssid) { tags.set(TagNumber::Ssid, ssid); }
	void setChannel(uint8_t channel) { tags.set(TagNumber::DsParameter, std::span<const uint8_t>(&channel, 1)); }

	[[nodiscard]] size_t length() const;
	[[nodiscard]] std::vector<uint8_t> build() const;

	static std::optional<Beacon> parse(const Frame& frame);
	// Security, SSID, channel etc. (libwifi_parse_beacon)
	static std::optional<Bss> parseBss(const Frame& frame);
};

} // namespace Wifi
