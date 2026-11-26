#include "Bss.h"

#include <algorithm>

namespace Wifi
{

void BssFixedParameters::write(ByteWriter& w) const
{
	w.le64(timestamp);
	w.le16(interval);
	w.le16(capabilities);
}

BssFixedParameters BssFixedParameters::read(ByteReader& r)
{
	BssFixedParameters p;
	p.timestamp = r.le64();
	p.interval = r.le16();
	p.capabilities = r.le16();
	return p;
}

std::optional<Bss> Bss::parse(const Frame& frame)
{
	if (!frame.is(ManagementSubtype::Beacon) && !frame.is(ManagementSubtype::ProbeResp))
		return std::nullopt;

	ByteReader r(frame.body());
	const auto fixed = BssFixedParameters::read(r);
	// libwifi also required at least one tag header after the fixed part
	if (!r.ok() || r.remaining() < TAG_HEADER_LENGTH)
		return std::nullopt;

	Bss bss;
	bss.receiver = frame.header().addr1;
	bss.transmitter = frame.header().addr2;
	bss.bssid = frame.header().addr3;
	bss.signal = frame.signal();
	bss.timestamp = fixed.timestamp;
	bss.beaconInterval = fixed.interval;
	bss.capabilities = fixed.capabilities;
	bss.readTags(Tags::parse(r.rest()), fixed.capabilities & Capability::Privacy);
	return bss;
}

void Bss::readTags(const Tags& source, const bool privacy)
{
	tags = source;
	encryptionInfo = privacy ? Wpa::Flag::Wep : 0;

	for (const Tag& tag : tags)
	{
		switch (static_cast<TagNumber>(tag.number))
		{
		case TagNumber::Ssid:
		{
			const size_t len = std::min(tag.data.size(), MAX_SSID_LENGTH);
			ssid.assign(tag.data.begin(), tag.data.begin() + static_cast<long>(len));
			hidden = std::ranges::all_of(ssid, [](char c) { return c == '\0'; });
			if (hidden)
				ssid.clear();
			break;
		}
		case TagNumber::DsParameter:
		case TagNumber::HtOperation:
			if (!tag.data.empty())
				channel = tag.data[0];
			break;
		case TagNumber::Rsn:
			if (auto info = Wpa::RsnInfo::parse(tag.data))
			{
				// An RSN element means it is not plain WEP
				encryptionInfo &= ~Wpa::Flag::Wep;
				encryptionInfo |= info->flags();
				rsn = std::move(info);
			}
			break;
		case TagNumber::VendorSpecific:
			if (tag.isVendor(Wpa::OUI_MICROSOFT, Wpa::MICROSOFT_TYPE_WPA))
			{
				encryptionInfo &= ~Wpa::Flag::Wep;
				encryptionInfo |= Wpa::Flag::Wpa;
				if (auto info = Wpa::WpaInfo::parse(std::span(tag.data).subspan(4)))
				{
					encryptionInfo |= info->flags();
					wpa = std::move(info);
				}
			}
			else if (tag.isVendor(Wpa::OUI_MICROSOFT, Wpa::MICROSOFT_TYPE_WPS))
				wps = true;
			break;
		default:
			break;
		}
	}
}

std::vector<uint8_t> Bss::supportedRates() const
{
	std::vector<uint8_t> rates;
	for (const Tag& tag : tags)
		if (tag.is(TagNumber::SupportedRates) || tag.is(TagNumber::ExtendedSupportedRates))
			rates.insert(rates.end(), tag.data.begin(), tag.data.end());
	return rates;
}

} // namespace Wifi
