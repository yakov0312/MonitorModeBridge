#include "Assoc.h"

namespace Wifi
{

/*---------*/
/* REQUEST */
/*---------*/

Assoc::Request Assoc::Request::create(const MacAddress& receiver, const MacAddress& transmitter,
	const MacAddress& bssid, const std::string_view ssid, const uint8_t channel)
{
	Request request;
	request.header = MacHeader::management(ManagementSubtype::AssocReq, receiver, transmitter, bssid);
	request.tags.reserve(TYPICAL_TAGS_LENGTH);
	request.setSsid(ssid);
	request.setChannel(channel);
	return request;
}

Assoc::Request Assoc::Request::createReassoc(const MacAddress& receiver, const MacAddress& transmitter,
	const MacAddress& bssid, const MacAddress& currentAp, const std::string_view ssid, const uint8_t channel)
{
	Request request;
	request.header = MacHeader::management(ManagementSubtype::ReassocReq, receiver, transmitter, bssid);
	request.currentAp = currentAp;
	request.tags.reserve(TYPICAL_TAGS_LENGTH);
	request.setSsid(ssid);
	request.setChannel(channel);
	return request;
}

std::vector<uint8_t> Assoc::Request::build() const
{
	std::vector<uint8_t> out;
	out.reserve(length());
	ByteWriter w(out);
	header.write(w);
	w.le16(capabilities);
	w.le16(listenInterval);
	if (isReassociation())
		w.mac(currentAp.value_or(MacAddress{}));
	tags.write(w);
	return out;
}

std::optional<Assoc::Request> Assoc::Request::parse(const Frame& frame)
{
	const bool reassoc = frame.is(ManagementSubtype::ReassocReq);
	if (!reassoc && !frame.is(ManagementSubtype::AssocReq))
		return std::nullopt;
	ByteReader r(frame.body());
	Request request;
	request.header = frame.header();
	request.capabilities = r.le16();
	request.listenInterval = r.le16();
	if (reassoc)
		request.currentAp = r.mac();
	if (!r.ok())
		return std::nullopt;
	request.tags = Tags::parse(r.rest());
	return request;
}

std::string Assoc::Request::ssid() const
{
	const auto tag = tags.find(TagNumber::Ssid);
	if (!tag)
		return {};
	return {tag->data.begin(), tag->data.end()};
}

std::optional<Wpa::RsnInfo> Assoc::Request::rsn() const
{
	const auto tag = tags.find(TagNumber::Rsn);
	if (!tag)
		return std::nullopt;
	return Wpa::RsnInfo::parse(tag->data);
}

/*----------*/
/* RESPONSE */
/*----------*/

Assoc::Response Assoc::Response::create(const MacAddress& receiver, const MacAddress& transmitter,
	const MacAddress& bssid, const uint8_t channel, const uint16_t aid, const bool reassociation)
{
	Response response;
	response.header = MacHeader::management(
		reassociation ? ManagementSubtype::ReassocResp : ManagementSubtype::AssocResp, receiver, transmitter, bssid);
	response.associationId = aid;
	response.tags.reserve(TYPICAL_TAGS_LENGTH);
	response.tags.set(TagNumber::DsParameter, std::span<const uint8_t>(&channel, 1));
	response.tags.add(TagNumber::SupportedRates, DEFAULT_SUPPORTED_RATES);
	return response;
}

std::vector<uint8_t> Assoc::Response::build() const
{
	std::vector<uint8_t> out;
	out.reserve(length());
	ByteWriter w(out);
	header.write(w);
	w.le16(capabilities);
	w.le16(static_cast<uint16_t>(status));
	w.le16(associationId);
	tags.write(w);
	return out;
}

std::optional<Assoc::Response> Assoc::Response::parse(const Frame& frame)
{
	if (!frame.is(ManagementSubtype::AssocResp) && !frame.is(ManagementSubtype::ReassocResp))
		return std::nullopt;
	ByteReader r(frame.body());
	Response response;
	response.header = frame.header();
	response.capabilities = r.le16();
	response.status = static_cast<StatusCode>(r.le16());
	response.associationId = r.le16();
	if (!r.ok())
		return std::nullopt;
	response.tags = Tags::parse(r.rest());
	return response;
}

} // namespace Wifi
