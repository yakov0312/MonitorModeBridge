// C++ replacement for libwifi: (re)association request / response frames.

#pragma once

#include "Frame.h"
#include "Tags.h"
#include "Wpa.h"

namespace Wifi
{

class Assoc
{
public:
	class Request
	{
	public:
		MacHeader header = MacHeader::management(ManagementSubtype::AssocReq, {}, {}, {});
		// libwifi used the AP default (ESS bit) here and APs accept it
		uint16_t capabilities = DEFAULT_AP_CAPABILITIES;
		uint16_t listenInterval = DEFAULT_LISTEN_INTERVAL;
		// Set only for a reassociation request
		std::optional<MacAddress> currentAp;
		Tags tags;

		// libwifi_create_assoc_req: SSID + DS Parameter Set tags
		static Request create(const MacAddress& receiver, const MacAddress& transmitter,
			const MacAddress& bssid, std::string_view ssid, uint8_t channel);
		// libwifi_create_reassoc_req
		static Request createReassoc(const MacAddress& receiver, const MacAddress& transmitter,
			const MacAddress& bssid, const MacAddress& currentAp, std::string_view ssid, uint8_t channel);

		void setSsid(std::string_view ssid) { tags.set(TagNumber::Ssid, ssid); }
		void setChannel(uint8_t channel) { tags.set(TagNumber::DsParameter, std::span<const uint8_t>(&channel, 1)); }
		void setSupportedRates(std::span<const uint8_t> rates) { tags.set(TagNumber::SupportedRates, rates); }
		void setRsn(const Wpa::RsnInfo& rsn) { tags.set(TagNumber::Rsn, rsn.build()); }

		[[nodiscard]] bool isReassociation() const { return header.frameControl.is(ManagementSubtype::ReassocReq); }
		[[nodiscard]] size_t fixedLength() const { return isReassociation() ? 10 : 4; }
		[[nodiscard]] size_t length() const { return header.length() + fixedLength() + tags.length(); }
		[[nodiscard]] std::vector<uint8_t> build() const;

		// Accepts association and reassociation requests
		static std::optional<Request> parse(const Frame& frame);

		[[nodiscard]] std::string ssid() const;
		[[nodiscard]] std::optional<Wpa::RsnInfo> rsn() const;
	};

	class Response
	{
	public:
		static constexpr size_t FIXED_LENGTH = 6; // capabilities + status + AID
		static constexpr uint16_t AID_MASK = 0x3FFF; // bits 14-15 are set on the air

		MacHeader header = MacHeader::management(ManagementSubtype::AssocResp, {}, {}, {});
		uint16_t capabilities = DEFAULT_AP_CAPABILITIES;
		StatusCode status = StatusCode::Success;
		uint16_t associationId = 0; // raw field, use aid() for the value
		Tags tags;

		// libwifi_create_assoc_resp: DS Parameter Set + default supported rates
		static Response create(const MacAddress& receiver, const MacAddress& transmitter,
			const MacAddress& bssid, uint8_t channel, uint16_t aid = 0, bool reassociation = false);

		[[nodiscard]] bool succeeded() const { return status == StatusCode::Success; }
		[[nodiscard]] uint16_t aid() const { return associationId & AID_MASK; }
		[[nodiscard]] bool isReassociation() const { return header.frameControl.is(ManagementSubtype::ReassocResp); }
		[[nodiscard]] size_t length() const { return header.length() + FIXED_LENGTH + tags.length(); }
		[[nodiscard]] std::vector<uint8_t> build() const;

		// Accepts association and reassociation responses
		static std::optional<Response> parse(const Frame& frame);
	};
};

} // namespace Wifi
