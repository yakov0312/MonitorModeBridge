#include "Probe.h"

namespace Wifi
{

/*---------*/
/* REQUEST */
/*---------*/

Probe::Request Probe::Request::create(const MacAddress& receiver, const MacAddress& transmitter,
	const MacAddress& bssid, const std::string_view ssid, const uint8_t channel)
{
	Request request;
	request.header = MacHeader::management(ManagementSubtype::ProbeReq, receiver, transmitter, bssid);
	request.setSsid(ssid);
	request.setChannel(channel);
	return request;
}

std::vector<uint8_t> Probe::Request::build() const
{
	std::vector<uint8_t> out;
	out.reserve(length());
	ByteWriter w(out);
	header.write(w);
	tags.write(w);
	return out;
}

std::optional<Probe::Request> Probe::Request::parse(const Frame& frame)
{
	if (!frame.is(ManagementSubtype::ProbeReq))
		return std::nullopt;
	Request request;
	request.header = frame.header();
	request.tags = Tags::parse(frame.body());
	return request;
}

std::string Probe::Request::ssid() const
{
	const Tag* tag = tags.find(TagNumber::Ssid);
	if (tag == nullptr)
		return {};
	return {tag->data.begin(), tag->data.end()};
}

std::optional<uint8_t> Probe::Request::channel() const
{
	const Tag* tag = tags.find(TagNumber::DsParameter);
	if (tag == nullptr || tag->data.empty())
		return std::nullopt;
	return tag->data[0];
}

/*----------*/
/* RESPONSE */
/*----------*/

Probe::Response Probe::Response::create(const MacAddress& receiver, const MacAddress& transmitter,
	const MacAddress& bssid, const std::string_view ssid, const uint8_t channel)
{
	Response response;
	response.header = MacHeader::management(ManagementSubtype::ProbeResp, receiver, transmitter, bssid);
	response.fixed.timestamp = currentTimestamp();
	response.setSsid(ssid);
	response.setChannel(channel);
	return response;
}

std::vector<uint8_t> Probe::Response::build() const
{
	std::vector<uint8_t> out;
	out.reserve(length());
	ByteWriter w(out);
	header.write(w);
	fixed.write(w);
	tags.write(w);
	return out;
}

std::optional<Probe::Response> Probe::Response::parse(const Frame& frame)
{
	if (!frame.is(ManagementSubtype::ProbeResp))
		return std::nullopt;
	ByteReader r(frame.body());
	Response response;
	response.header = frame.header();
	response.fixed = BssFixedParameters::read(r);
	if (!r.ok())
		return std::nullopt;
	response.tags = Tags::parse(r.rest());
	return response;
}

std::optional<Bss> Probe::Response::parseBss(const Frame& frame)
{
	if (!frame.is(ManagementSubtype::ProbeResp))
		return std::nullopt;
	return Bss::parse(frame);
}

} // namespace Wifi
