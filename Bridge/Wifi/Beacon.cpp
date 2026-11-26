#include "Beacon.h"

namespace Wifi
{

Beacon Beacon::create(const MacAddress& receiver, const MacAddress& transmitter, const MacAddress& bssid,
	const std::string_view ssid, const uint8_t channel)
{
	Beacon beacon;
	beacon.header = MacHeader::management(ManagementSubtype::Beacon, receiver, transmitter, bssid);
	beacon.fixed.timestamp = currentTimestamp();
	beacon.tags.reserve(TYPICAL_TAGS_LENGTH);
	beacon.setSsid(ssid);
	beacon.setChannel(channel);
	return beacon;
}

size_t Beacon::length() const
{
	return header.length() + BssFixedParameters::LENGTH + tags.length();
}

std::vector<uint8_t> Beacon::build() const
{
	std::vector<uint8_t> out;
	out.reserve(length());
	ByteWriter w(out);
	header.write(w);
	fixed.write(w);
	tags.write(w);
	return out;
}

std::optional<Beacon> Beacon::parse(const Frame& frame)
{
	if (!frame.is(ManagementSubtype::Beacon))
		return std::nullopt;
	ByteReader r(frame.body());
	Beacon beacon;
	beacon.header = frame.header();
	beacon.fixed = BssFixedParameters::read(r);
	if (!r.ok())
		return std::nullopt;
	beacon.tags = Tags::parse(r.rest());
	return beacon;
}

std::optional<Bss> Beacon::parseBss(const Frame& frame)
{
	if (!frame.is(ManagementSubtype::Beacon))
		return std::nullopt;
	return Bss::parse(frame);
}

} // namespace Wifi
