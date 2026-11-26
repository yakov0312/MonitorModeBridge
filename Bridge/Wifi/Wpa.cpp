#include "Wpa.h"

#include <algorithm>

namespace Wifi
{

using CS = Wpa::CipherSuite;
using AKM = Wpa::AkmSuite;
using F = Wpa::Flag;

/*-------*/
/* FLAGS */
/*-------*/

uint64_t Wpa::groupCipherFlag(const uint8_t suiteType)
{
	switch (static_cast<CS>(suiteType))
	{
	case CS::Wep40: return F::GroupWep40;
	case CS::Tkip: return F::GroupTkip;
	case CS::Reserved: return F::GroupReserved;
	case CS::Ccmp128: return F::GroupCcmp128;
	case CS::Wep104: return F::GroupWep104;
	case CS::BipCmac128: return F::GroupBipCmac128;
	case CS::GroupNotAllowed: return F::GroupNotAllowed;
	case CS::Gcmp128: return F::GroupGcmp128;
	case CS::Gcmp256: return F::GroupGcmp256;
	case CS::Ccmp256: return F::GroupCcmp256;
	case CS::BipGmac128: return F::GroupBipGmac128;
	case CS::BipGmac256: return F::GroupBipGmac256;
	case CS::BipCmac256: return F::GroupBipCmac256;
	default: return 0;
	}
}

uint64_t Wpa::pairwiseCipherFlag(const uint8_t suiteType)
{
	switch (static_cast<CS>(suiteType))
	{
	case CS::UseGroup: return F::PairwiseUseGroup;
	case CS::Wep40: return F::PairwiseWep40;
	case CS::Tkip: return F::PairwiseTkip;
	case CS::Reserved: return F::PairwiseReserved;
	case CS::Ccmp128: return F::PairwiseCcmp128;
	case CS::Wep104: return F::PairwiseWep104;
	case CS::BipCmac128: return F::PairwiseBipCmac128;
	case CS::GroupNotAllowed: return F::PairwiseNotAllowed;
	case CS::Gcmp128: return F::PairwiseGcmp128;
	case CS::Gcmp256: return F::PairwiseGcmp256;
	case CS::Ccmp256: return F::PairwiseCcmp256;
	case CS::BipGmac128: return F::PairwiseBipGmac128;
	case CS::BipGmac256: return F::PairwiseBipGmac256;
	case CS::BipCmac256: return F::PairwiseBipCmac256;
	default: return 0;
	}
}

uint64_t Wpa::akmFlag(const uint8_t suiteType)
{
	switch (static_cast<AKM>(suiteType))
	{
	case AKM::Reserved: return F::Wpa2 | F::AkmReserved;
	case AKM::Ieee8021x: return F::Wpa2 | F::Akm8021x;
	case AKM::Psk: return F::Wpa2 | F::AkmPsk;
	case AKM::FtIeee8021x: return F::Wpa2 | F::AkmFt8021x;
	case AKM::FtPsk: return F::Wpa2 | F::AkmFtPsk;
	case AKM::Ieee8021xSha256: return F::Wpa2 | F::Akm8021xSha256;
	case AKM::PskSha256: return F::Wpa2 | F::AkmPskSha256;
	case AKM::Tdls: return F::Wpa2 | F::AkmTdls;
	case AKM::Sae: return F::Wpa3 | F::AkmSae;
	case AKM::FtSae: return F::Wpa3 | F::AkmFtSae;
	case AKM::ApPeerKey: return F::Wpa3 | F::AkmApPeerKey;
	case AKM::Ieee8021xSuiteBSha256: return F::Wpa3 | F::Akm8021xSuiteBSha256;
	case AKM::Ieee8021xSuiteBSha384: return F::Wpa3 | F::Akm8021xSuiteBSha384;
	case AKM::FtIeee8021xSha384: return F::Wpa3 | F::AkmFt8021xSha384;
	case AKM::FilsSha256: return F::Wpa2 | F::AkmFilsSha256;
	case AKM::FilsSha384: return F::Wpa3 | F::AkmFilsSha384;
	case AKM::FtFilsSha256: return F::Wpa2 | F::AkmFtFilsSha256;
	case AKM::FtFilsSha384: return F::Wpa3 | F::AkmFtFilsSha384;
	case AKM::Owe: return F::Wpa3 | F::AkmOwe;
	case AKM::FtPskSha384: return F::Wpa3 | F::AkmFtPskSha384;
	case AKM::PskSha384: return F::Wpa3 | F::AkmPskSha384;
	case AKM::SaeExtKey: return F::Wpa3 | F::AkmSaeExtKey;
	case AKM::FtSaeExtKey: return F::Wpa3 | F::AkmFtSaeExtKey;
	default: return 0;
	}
}

namespace
{
	struct FlagName
	{
		uint64_t flag;
		const char* name;
	};

	std::string joinNames(const uint64_t flags, const std::initializer_list<FlagName> names)
	{
		if (flags == 0)
			return "None";
		std::string out;
		for (const auto& [flag, name] : names)
		{
			if (!(flags & flag))
				continue;
			if (!out.empty())
				out += ", ";
			out += name;
		}
		return out;
	}
}

std::string Wpa::securityTypes(const uint64_t flags)
{
	return joinNames(flags, {{F::Wpa3, "WPA3"}, {F::Wpa2, "WPA2"}, {F::Wpa, "WPA"}, {F::Wep, "WEP"}});
}

std::string Wpa::groupCiphers(const uint64_t flags)
{
	return joinNames(flags, {
		{F::GroupWep40, "WEP40"}, {F::GroupTkip, "TKIP"}, {F::GroupReserved, "RESERVED"},
		{F::GroupCcmp128, "CCMP128"}, {F::GroupWep104, "WEP104"}, {F::GroupBipCmac128, "BIP_CMAC128"},
		{F::GroupNotAllowed, "NOT_ALLOWED"}, {F::GroupGcmp128, "GCMP128"}, {F::GroupGcmp256, "GCMP256"},
		{F::GroupCcmp256, "CCMP256"}, {F::GroupBipGmac128, "BIP_GMAC128"}, {F::GroupBipGmac256, "BIP_GMAC256"},
		{F::GroupBipCmac256, "BIP_CMAC256"}});
}

std::string Wpa::pairwiseCiphers(const uint64_t flags)
{
	return joinNames(flags, {
		{F::PairwiseUseGroup, "GROUP"}, {F::PairwiseWep40, "WEP40"}, {F::PairwiseTkip, "TKIP"},
		{F::PairwiseReserved, "RESERVED"}, {F::PairwiseCcmp128, "CCMP128"}, {F::PairwiseWep104, "WEP104"},
		{F::PairwiseBipCmac128, "BIP_CMAC128"}, {F::PairwiseNotAllowed, "NOT_ALLOWED"},
		{F::PairwiseGcmp128, "GCMP128"}, {F::PairwiseGcmp256, "GCMP256"}, {F::PairwiseCcmp256, "CCMP256"},
		{F::PairwiseBipGmac128, "BIP_GMAC128"}, {F::PairwiseBipGmac256, "BIP_GMAC256"},
		{F::PairwiseBipCmac256, "BIP_CMAC256"}});
}

std::string Wpa::akmSuites(const uint64_t flags)
{
	return joinNames(flags, {
		{F::AkmReserved, "RESERVED"}, {F::Akm8021x, "802.1X"}, {F::AkmPsk, "PSK"},
		{F::AkmFt8021x, "802.1X_FT"}, {F::AkmFtPsk, "PSK_FT"}, {F::Akm8021xSha256, "802.1X_SHA256"},
		{F::AkmPskSha256, "PSK_SHA256"}, {F::AkmTdls, "TDLS"}, {F::AkmSae, "SAE"}, {F::AkmFtSae, "SAE_FT"},
		{F::AkmApPeerKey, "AP_PEER"}, {F::Akm8021xSuiteBSha256, "802.1X_SUITEB_SHA256"},
		{F::Akm8021xSuiteBSha384, "802.1X_SUITEB_SHA384"}, {F::AkmFt8021xSha384, "802.1X_FT_SHA384"},
		{F::AkmFilsSha256, "FILS_SHA256"}, {F::AkmFilsSha384, "FILS_SHA384"},
		{F::AkmFtFilsSha256, "FILS_SHA256_FT"}, {F::AkmFtFilsSha384, "FILS_SHA384_FT"}, {F::AkmOwe, "OWE"},
		{F::AkmFtPskSha384, "PSK_SHA384_FT"}, {F::AkmPskSha384, "PSK_SHA384"},
		{F::AkmSaeExtKey, "SAE_EXT_KEY"}, {F::AkmFtSaeExtKey, "SAE_EXT_KEY_FT"}});
}

/*----------*/
/* RSN INFO */
/*----------*/

namespace
{
	Wpa::Suite readSuite(ByteReader& r)
	{
		Wpa::Suite suite;
		const auto oui = r.bytes(3);
		if (oui.size() == 3)
			std::copy(oui.begin(), oui.end(), suite.oui.begin());
		suite.type = r.u8();
		return suite;
	}

	void writeSuite(ByteWriter& w, const Wpa::Suite& suite)
	{
		w.bytes(suite.oui);
		w.u8(suite.type);
	}

	// count (le16) + count suites. False when the list is truncated.
	bool readSuiteList(ByteReader& r, std::vector<Wpa::Suite>& out)
	{
		const uint16_t count = r.le16();
		if (!r.ok() || r.remaining() < static_cast<size_t>(count) * 4)
			return false;
		out.reserve(count);
		for (uint16_t i = 0; i < count; i++)
			out.push_back(readSuite(r));
		return r.ok();
	}

	void writeSuiteList(ByteWriter& w, const std::vector<Wpa::Suite>& suites)
	{
		w.le16(static_cast<uint16_t>(suites.size()));
		for (const auto& suite : suites)
			writeSuite(w, suite);
	}
}

Wpa::RsnInfo Wpa::RsnInfo::create(const CipherSuite group, const CipherSuite pairwise, const AkmSuite akm,
	const uint16_t capabilities)
{
	RsnInfo info;
	info.groupCipher = Suite::cipher(group);
	info.pairwiseCiphers = {Suite::cipher(pairwise)};
	info.akmSuites = {Suite::akm(akm)};
	info.capabilities = capabilities;
	return info;
}

std::optional<Wpa::RsnInfo> Wpa::RsnInfo::parse(const std::span<const uint8_t> body)
{
	ByteReader r(body);
	RsnInfo info;
	info.version = r.le16();
	info.groupCipher = readSuite(r);
	if (!r.ok())
		return std::nullopt;

	if (r.remaining() >= 2 && !readSuiteList(r, info.pairwiseCiphers))
		return std::nullopt;
	if (r.remaining() >= 2 && !readSuiteList(r, info.akmSuites))
		return std::nullopt;
	if (r.remaining() >= 2)
		info.capabilities = r.le16();
	if (r.remaining() >= 2)
	{
		const uint16_t count = r.le16();
		if (r.remaining() < static_cast<size_t>(count) * 16)
			return std::nullopt;
		for (uint16_t i = 0; i < count; i++)
		{
			Pmkid pmkid{};
			const auto raw = r.bytes(pmkid.size());
			std::copy(raw.begin(), raw.end(), pmkid.begin());
			info.pmkids.push_back(pmkid);
		}
	}
	if (r.remaining() >= 4)
		info.groupManagementCipher = readSuite(r);

	return info;
}

std::vector<uint8_t> Wpa::RsnInfo::build() const
{
	std::vector<uint8_t> out;
	ByteWriter w(out);
	w.le16(version);
	writeSuite(w, groupCipher);
	writeSuiteList(w, pairwiseCiphers);
	writeSuiteList(w, akmSuites);
	w.le16(capabilities);
	if (!pmkids.empty() || groupManagementCipher)
	{
		w.le16(static_cast<uint16_t>(pmkids.size()));
		for (const auto& pmkid : pmkids)
			w.bytes(pmkid);
	}
	if (groupManagementCipher)
		writeSuite(w, *groupManagementCipher);
	return out;
}

uint64_t Wpa::RsnInfo::flags() const
{
	uint64_t flags = groupCipherFlag(groupCipher.type);
	for (const Suite& suite : pairwiseCiphers)
		if (suite.isIeee())
			flags |= pairwiseCipherFlag(suite.type);
	for (const Suite& suite : akmSuites)
		if (suite.isIeee())
			flags |= akmFlag(suite.type);
	return flags;
}

bool Wpa::RsnInfo::hasPairwise(const CipherSuite c) const
{
	return std::ranges::find(pairwiseCiphers, Suite::cipher(c)) != pairwiseCiphers.end();
}

bool Wpa::RsnInfo::hasAkm(const AkmSuite a) const
{
	return std::ranges::find(akmSuites, Suite::akm(a)) != akmSuites.end();
}

/*----------*/
/* WPA INFO */
/*----------*/

std::optional<Wpa::WpaInfo> Wpa::WpaInfo::parse(const std::span<const uint8_t> body)
{
	ByteReader r(body);
	WpaInfo info;
	info.version = r.le16();
	info.multicastCipher = readSuite(r);
	if (!r.ok())
		return std::nullopt;
	if (r.remaining() >= 2 && !readSuiteList(r, info.unicastCiphers))
		return std::nullopt;
	if (r.remaining() >= 2 && !readSuiteList(r, info.akmSuites))
		return std::nullopt;
	return info;
}

uint64_t Wpa::WpaInfo::flags() const
{
	uint64_t flags = groupCipherFlag(multicastCipher.type);
	for (const Suite& suite : unicastCiphers)
		if (suite.isMicrosoft())
			flags |= pairwiseCipherFlag(suite.type);
	for (const Suite& suite : akmSuites)
	{
		// WPA1 only defines AKMs 0-4; they mean WPA, not WPA2
		if (suite.isMicrosoft() && suite.type <= static_cast<uint8_t>(AKM::FtPsk))
			flags |= F::Wpa | (akmFlag(suite.type) & ~F::Wpa2);
	}
	return flags;
}

/*-------*/
/* EAPOL */
/*-------*/

const char* Wpa::messageName(const HandshakeMessage message)
{
	switch (message)
	{
	case HandshakeMessage::M1: return "Message 1";
	case HandshakeMessage::M2: return "Message 2";
	case HandshakeMessage::M3: return "Message 3";
	case HandshakeMessage::M4: return "Message 4";
	case HandshakeMessage::GroupM1: return "Group Message 1";
	case HandshakeMessage::GroupM2: return "Group Message 2";
	default: return "Invalid";
	}
}

std::optional<Wpa::EapolKey> Wpa::EapolKey::parse(const std::span<const uint8_t> eapol, const size_t micLength)
{
	ByteReader r(eapol);
	EapolKey key;
	key.version = r.u8();
	key.type = static_cast<EapolType>(r.u8());
	r.be16(); // body length; APs sometimes pad, so it is not trusted
	if (!r.ok() || key.type != EapolType::Key)
		return std::nullopt;

	key.descriptor = static_cast<KeyDescriptor>(r.u8());
	key.keyInformation = r.be16();
	key.keyLength = r.be16();
	key.replayCounter = r.be64();

	auto copyInto = [&r](auto& array) {
		const auto raw = r.bytes(array.size());
		if (raw.size() == array.size())
			std::copy(raw.begin(), raw.end(), array.begin());
	};
	copyInto(key.nonce);
	copyInto(key.iv);
	copyInto(key.rsc);
	copyInto(key.id);

	const auto mic = r.bytes(micLength);
	key.mic.assign(mic.begin(), mic.end());

	const uint16_t keyDataLength = r.be16();
	const auto keyData = r.bytes(keyDataLength);
	key.keyData.assign(keyData.begin(), keyData.end());

	if (!r.ok())
		return std::nullopt;
	return key;
}

std::optional<Wpa::EapolKey> Wpa::EapolKey::parse(const Frame& frame, const size_t micLength)
{
	if (!isEapol(frame))
		return std::nullopt;
	return parse(frame.body().subspan(LLC_SNAP_EAPOL.size()), micLength);
}

Wpa::HandshakeMessage Wpa::EapolKey::message() const
{
	if (has(KeyInfo::Request) || has(KeyInfo::Error))
		return HandshakeMessage::Invalid;

	const bool hasAck = has(KeyInfo::Ack);
	const bool hasMic = has(KeyInfo::Mic);

	if (!has(KeyInfo::Pairwise))
	{
		if (hasAck && hasMic)
			return HandshakeMessage::GroupM1;
		if (hasMic)
			return HandshakeMessage::GroupM2;
		return HandshakeMessage::Invalid;
	}

	if (hasAck)
		return hasMic ? HandshakeMessage::M3 : HandshakeMessage::M1;
	if (!hasMic)
		return HandshakeMessage::Invalid;

	// M2 and M4 both come from the station. M4 has Secure set (RSN), and in
	// WPA1 it is the one without a nonce and without key data.
	if (has(KeyInfo::Secure))
		return HandshakeMessage::M4;
	const bool noNonce = std::ranges::all_of(nonce, [](uint8_t b) { return b == 0; });
	return (noNonce && keyData.empty()) ? HandshakeMessage::M4 : HandshakeMessage::M2;
}

size_t Wpa::EapolKey::length() const
{
	return micOffset() + mic.size() + 2 + keyData.size();
}

std::vector<uint8_t> Wpa::EapolKey::build() const
{
	std::vector<uint8_t> out;
	out.reserve(length());
	ByteWriter w(out);
	w.u8(version);
	w.u8(static_cast<uint8_t>(type));
	w.be16(static_cast<uint16_t>(length() - EAPOL_HEADER_LENGTH));
	w.u8(static_cast<uint8_t>(descriptor));
	w.be16(keyInformation);
	w.be16(keyLength);
	w.be64(replayCounter);
	w.bytes(nonce);
	w.bytes(iv);
	w.bytes(rsc);
	w.bytes(id);
	w.bytes(mic);
	w.be16(static_cast<uint16_t>(keyData.size()));
	w.bytes(keyData);
	return out;
}

std::vector<uint8_t> Wpa::EapolKey::buildDataFrame(const MacAddress& bssid, const MacAddress& station,
	const uint16_t sequence) const
{
	MacHeader header;
	header.frameControl = FrameControl(DataSubtype::Data, FrameFlag::ToDs);
	header.addr1 = bssid;   // receiver = AP
	header.addr2 = station; // transmitter = us
	header.addr3 = bssid;   // destination
	header.sequenceControl.sequence = sequence;

	std::vector<uint8_t> out;
	ByteWriter w(out);
	header.write(w);
	w.bytes(LLC_SNAP_EAPOL);
	w.bytes(build());
	return out;
}

bool Wpa::isEapol(const Frame& frame)
{
	if (frame.type() != FrameType::Data || frame.frameControl().isProtected())
		return false;
	const auto body = frame.body();
	// LLC/SNAP + EAPOL header + the fixed part of the key descriptor
	if (body.size() < LLC_SNAP_EAPOL.size() + EapolKey::micOffset() + DEFAULT_MIC_LENGTH + 2)
		return false;
	return std::equal(LLC_SNAP_EAPOL.begin(), LLC_SNAP_EAPOL.end(), body.begin()) &&
		body[LLC_SNAP_EAPOL.size() + 1] == static_cast<uint8_t>(EapolType::Key);
}

Wpa::HandshakeMessage Wpa::message(const Frame& frame)
{
	const auto key = EapolKey::parse(frame);
	return key ? key->message() : HandshakeMessage::Invalid;
}

} // namespace Wifi
