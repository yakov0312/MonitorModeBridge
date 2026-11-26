// C++ replacement for libwifi: authentication, deauthentication and
// disassociation frames.

#pragma once

#include "Frame.h"
#include "Tags.h"

namespace Wifi
{

class Auth
{
public:
	static constexpr size_t FIXED_LENGTH = 6; // algorithm + sequence + status
	static constexpr uint16_t SEQUENCE_REQUEST = 1;
	static constexpr uint16_t SEQUENCE_RESPONSE = 2;

	MacHeader header = MacHeader::management(ManagementSubtype::Auth, {}, {}, {});
	AuthAlgorithm algorithm = AuthAlgorithm::Open;
	uint16_t transactionSequence = SEQUENCE_REQUEST;
	StatusCode status = StatusCode::Success;
	// Everything after the fixed parameters. For Open/Shared Key these are
	// tags (elements()); for SAE they are the commit/confirm fields.
	std::vector<uint8_t> payload;

	// libwifi_create_auth
	static Auth create(const MacAddress& receiver, const MacAddress& transmitter, const MacAddress& bssid,
		AuthAlgorithm algorithm = AuthAlgorithm::Open, uint16_t transactionSequence = SEQUENCE_REQUEST,
		StatusCode status = StatusCode::Success);

	[[nodiscard]] Tags elements() const { return Tags::parse(payload); }
	void setElements(const Tags& tags) { payload = tags.serialize(); }

	[[nodiscard]] bool succeeded() const { return status == StatusCode::Success; }
	[[nodiscard]] size_t length() const { return header.length() + FIXED_LENGTH + payload.size(); }
	[[nodiscard]] std::vector<uint8_t> build() const;

	static std::optional<Auth> parse(const Frame& frame);

	// Deauthentication and disassociation share one layout: a reason code
	// and optional elements.
	class Deauth
	{
	public:
		MacHeader header = MacHeader::management(ManagementSubtype::Deauth, {}, {}, {});
		ReasonCode reason = ReasonCode::UnspecifiedFailure;
		Tags tags;

		// libwifi_create_deauth / libwifi_create_disassoc
		static Deauth create(const MacAddress& receiver, const MacAddress& transmitter, const MacAddress& bssid,
			ReasonCode reason, bool disassociation = false);

		[[nodiscard]] bool isDisassociation() const { return header.frameControl.is(ManagementSubtype::Disassoc); }
		[[nodiscard]] size_t length() const { return header.length() + sizeof(uint16_t) + tags.length(); }
		[[nodiscard]] std::vector<uint8_t> build() const;

		// Accepts both deauthentication and disassociation frames
		static std::optional<Deauth> parse(const Frame& frame);
	};
};

} // namespace Wifi
