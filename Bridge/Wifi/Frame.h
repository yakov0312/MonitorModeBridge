// C++ replacement for libwifi: a received 802.11 frame.
//
// Unlike libwifi_frame this owns its bytes: copy it, move it, keep it in a
// queue, and nothing has to be freed. Parsing costs one allocation (the
// copy of the captured bytes); the radiotap header is kept raw and only
// decoded when radiotap() is called.

#pragma once

#include "Common.h"
#include "Radiotap.h"

namespace Wifi
{

class Frame
{
public:
	// Parses a captured frame. With hasRadiotap the radiotap header is read
	// and skipped, and a trailing FCS is cut off when radiotap says there is
	// one. Returns nullopt for truncated frames and extension frames.
	static std::optional<Frame> parse(std::span<const uint8_t> data, bool hasRadiotap = true);

	[[nodiscard]] const MacHeader& header() const { return m_header; }
	[[nodiscard]] const FrameControl& frameControl() const { return m_header.frameControl; }
	[[nodiscard]] FrameType type() const { return m_header.frameControl.type; }
	[[nodiscard]] uint8_t subtype() const { return m_header.frameControl.subtype; }
	[[nodiscard]] bool is(ManagementSubtype s) const { return m_header.frameControl.is(s); }
	[[nodiscard]] bool is(ControlSubtype s) const { return m_header.frameControl.is(s); }
	[[nodiscard]] bool is(DataSubtype s) const { return m_header.frameControl.is(s); }
	[[nodiscard]] bool isRetry() const { return m_header.frameControl.retry(); }
	[[nodiscard]] bool isQos() const { return m_header.qosControl.has_value(); }
	[[nodiscard]] bool isOrdered() const { return m_header.htControl.has_value(); }

	[[nodiscard]] const MacAddress& receiver() const { return m_header.receiver(); }
	[[nodiscard]] const MacAddress& transmitter() const { return m_header.transmitter(); }
	[[nodiscard]] MacAddress bssid() const { return m_header.bssid(); }
	[[nodiscard]] MacAddress destination() const { return m_header.destination(); }
	[[nodiscard]] MacAddress source() const { return m_header.source(); }

	// The 802.11 frame without radiotap and without FCS
	[[nodiscard]] std::span<const uint8_t> bytes() const { return std::span(m_raw).subspan(m_radiotapLength); }
	[[nodiscard]] size_t length() const { return m_raw.size() - m_radiotapLength; }
	[[nodiscard]] size_t headerLength() const { return m_headerLength; }
	// Everything after the MAC header (fixed parameters, tags, payload)
	[[nodiscard]] std::span<const uint8_t> body() const { return bytes().subspan(m_headerLength); }

	// Decodes the radiotap header (nullopt if the frame had none)
	[[nodiscard]] std::optional<RadiotapInfo> radiotap() const;
	[[nodiscard]] std::span<const uint8_t> radiotapBytes() const { return std::span(m_raw).first(m_radiotapLength); }
	[[nodiscard]] bool hasFcs() const { return m_fcs.has_value(); }
	[[nodiscard]] std::optional<uint32_t> fcs() const { return m_fcs; }
	// Signal in dBm from radiotap, if the driver reported it
	[[nodiscard]] std::optional<int8_t> signal() const;

private:
	Frame() = default;

	MacHeader m_header;
	uint16_t m_headerLength = 0;
	uint16_t m_radiotapLength = 0;
	std::vector<uint8_t> m_raw; // radiotap + 802.11 frame, FCS cut off
	std::optional<uint32_t> m_fcs;
};

// 802.11 CRC-32 (the FCS) over data
uint32_t crc32(std::span<const uint8_t> data);

} // namespace Wifi
