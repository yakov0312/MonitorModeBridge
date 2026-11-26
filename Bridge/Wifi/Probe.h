// C++ replacement for libwifi: probe request / probe response frames.

#pragma once

#include "Bss.h"

namespace Wifi
{

class Probe
{
public:
	class Request
	{
	public:
		MacHeader header = MacHeader::management(ManagementSubtype::ProbeReq, BROADCAST, {}, BROADCAST);
		Tags tags;

		// libwifi_create_probe_req: SSID tag, then DS Parameter Set
		// (channel), so the channel is the last byte of build()
		static Request create(const MacAddress& receiver, const MacAddress& transmitter,
			const MacAddress& bssid, std::string_view ssid, uint8_t channel);

		void setSsid(std::string_view ssid) { tags.set(TagNumber::Ssid, ssid); }
		void setChannel(uint8_t channel) { tags.set(TagNumber::DsParameter, std::span<const uint8_t>(&channel, 1)); }

		[[nodiscard]] size_t length() const { return header.length() + tags.length(); }
		[[nodiscard]] std::vector<uint8_t> build() const;

		static std::optional<Request> parse(const Frame& frame);

		[[nodiscard]] std::string ssid() const;
		[[nodiscard]] bool isWildcard() const { return ssid().empty(); }
		[[nodiscard]] std::optional<uint8_t> channel() const;
		[[nodiscard]] bool isRandomizedMac() const { return Wifi::isRandomizedMac(header.addr2); }
	};

	class Response
	{
	public:
		MacHeader header = MacHeader::management(ManagementSubtype::ProbeResp, {}, {}, {});
		BssFixedParameters fixed;
		Tags tags;

		// libwifi_create_probe_resp: SSID + DS Parameter Set, interval 100,
		// ESS capability, current time as the timestamp
		static Response create(const MacAddress& receiver, const MacAddress& transmitter,
			const MacAddress& bssid, std::string_view ssid, uint8_t channel);

		void setSsid(std::string_view ssid) { tags.set(TagNumber::Ssid, ssid); }
		void setChannel(uint8_t channel) { tags.set(TagNumber::DsParameter, std::span<const uint8_t>(&channel, 1)); }

		[[nodiscard]] size_t length() const { return header.length() + BssFixedParameters::LENGTH + tags.length(); }
		[[nodiscard]] std::vector<uint8_t> build() const;

		static std::optional<Response> parse(const Frame& frame);
		// Security, SSID, channel etc. (libwifi_parse_probe_resp)
		static std::optional<Bss> parseBss(const Frame& frame);
	};
};

} // namespace Wifi
