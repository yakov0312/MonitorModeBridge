#include "Auth.h"

namespace Wifi
{

Auth Auth::create(const MacAddress& receiver, const MacAddress& transmitter, const MacAddress& bssid,
	const AuthAlgorithm algorithm, const uint16_t transactionSequence, const StatusCode status)
{
	Auth auth;
	auth.header = MacHeader::management(ManagementSubtype::Auth, receiver, transmitter, bssid);
	auth.algorithm = algorithm;
	auth.transactionSequence = transactionSequence;
	auth.status = status;
	return auth;
}

std::vector<uint8_t> Auth::build() const
{
	std::vector<uint8_t> out;
	out.reserve(length());
	ByteWriter w(out);
	header.write(w);
	w.le16(static_cast<uint16_t>(algorithm));
	w.le16(transactionSequence);
	w.le16(static_cast<uint16_t>(status));
	w.bytes(payload);
	return out;
}

std::optional<Auth> Auth::parse(const Frame& frame)
{
	if (!frame.is(ManagementSubtype::Auth))
		return std::nullopt;
	ByteReader r(frame.body());
	Auth auth;
	auth.header = frame.header();
	auth.algorithm = static_cast<AuthAlgorithm>(r.le16());
	auth.transactionSequence = r.le16();
	auth.status = static_cast<StatusCode>(r.le16());
	if (!r.ok())
		return std::nullopt;
	const auto rest = r.rest();
	auth.payload.assign(rest.begin(), rest.end());
	return auth;
}

/*--------------------------*/
/* DEAUTH / DISASSOCIATION  */
/*--------------------------*/

Auth::Deauth Auth::Deauth::create(const MacAddress& receiver, const MacAddress& transmitter,
	const MacAddress& bssid, const ReasonCode reason, const bool disassociation)
{
	Deauth deauth;
	deauth.header = MacHeader::management(
		disassociation ? ManagementSubtype::Disassoc : ManagementSubtype::Deauth, receiver, transmitter, bssid);
	deauth.reason = reason;
	return deauth;
}

std::vector<uint8_t> Auth::Deauth::build() const
{
	std::vector<uint8_t> out;
	out.reserve(length());
	ByteWriter w(out);
	header.write(w);
	w.le16(static_cast<uint16_t>(reason));
	tags.write(w);
	return out;
}

std::optional<Auth::Deauth> Auth::Deauth::parse(const Frame& frame)
{
	if (!frame.is(ManagementSubtype::Deauth) && !frame.is(ManagementSubtype::Disassoc))
		return std::nullopt;
	ByteReader r(frame.body());
	Deauth deauth;
	deauth.header = frame.header();
	deauth.reason = static_cast<ReasonCode>(r.le16());
	if (!r.ok())
		return std::nullopt;
	deauth.tags = Tags::parse(r.rest());
	return deauth;
}

} // namespace Wifi
