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

// libwifi's bit layout is "base + suite type", so the suite -> flag mapping
// is arithmetic: group ciphers start at bit 4, pairwise at 18, AKMs at 32
// (bit 38 skipped). The names below are indexed the same way.
namespace
{
	constexpr unsigned GROUP_BASE = 4;
	constexpr unsigned PAIRWISE_BASE = 18;
	constexpr unsigned AKM_BASE = 32;
	constexpr uint8_t LAST_CIPHER = 13; // BIP-CMAC-256
	constexpr uint8_t LAST_AKM = 20;    // PSK-SHA384

	// AKMs that mean WPA3 rather than WPA2
	constexpr uint32_t WPA3_AKMS = 1u << 8 | 1u << 9 | 1u << 10 | 1u << 11 | 1u << 12 | 1u << 13 |
		1u << 15 | 1u << 17 | 1u << 18 | 1u << 19 | 1u << 20 | 1u << 24 | 1u << 25;

	constexpr const char* CIPHER_NAMES[] = {"GROUP", "WEP40", "TKIP", "RESERVED", "CCMP128", "WEP104",
		"BIP_CMAC128", "NOT_ALLOWED", "GCMP128", "GCMP256", "CCMP256", "BIP_GMAC128", "BIP_GMAC256", "BIP_CMAC256"};
	constexpr const char* AKM_NAMES[] = {"RESERVED", "802.1X", "PSK", "802.1X_FT", "PSK_FT", "802.1X_SHA256",
		"PSK_SHA256", "TDLS", "SAE", "SAE_FT", "AP_PEER", "802.1X_SUITEB_SHA256", "802.1X_SUITEB_SHA384",
		"802.1X_FT_SHA384", "FILS_SHA256", "FILS_SHA384", "FILS_SHA256_FT", "FILS_SHA384_FT", "OWE",
		"PSK_SHA384_FT", "PSK_SHA384"};

	unsigned akmBit(const uint8_t type)
	{
		return AKM_BASE + type + (type >= 6 ? 1 : 0);
	}

	void append(std::string& out, const char* name)
	{
		if (!out.empty())
			out += ", ";
		out += name;
	}
}

uint64_t Wpa::groupCipherFlag(const uint8_t suiteType)
{
	// Type 0 ("use group") makes no sense for the group cipher itself
	return suiteType >= 1 && suiteType <= LAST_CIPHER ? 1ULL << (GROUP_BASE + suiteType) : 0;
}

uint64_t Wpa::pairwiseCipherFlag(const uint8_t suiteType)
{
	return suiteType <= LAST_CIPHER ? 1ULL << (PAIRWISE_BASE + suiteType) : 0;
}

uint64_t Wpa::akmFlag(const uint8_t suiteType)
{
	uint64_t flag;
	if (suiteType <= LAST_AKM)
		flag = 1ULL << akmBit(suiteType);
	else if (suiteType == static_cast<uint8_t>(AKM::SaeExtKey))
		flag = F::AkmSaeExtKey;
	else if (suiteType == static_cast<uint8_t>(AKM::FtSaeExtKey))
		flag = F::AkmFtSaeExtKey;
	else
		return 0;
	return flag | ((WPA3_AKMS >> suiteType & 1) ? F::Wpa3 : F::Wpa2);
}

std::string Wpa::securityTypes(const uint64_t flags)
{
	if (flags == 0)
		return "None";
	std::string out;
	for (const auto& [flag, name] : {std::pair{F::Wpa3, "WPA3"}, {F::Wpa2, "WPA2"}, {F::Wpa, "WPA"}, {F::Wep, "WEP"}})
		if (flags & flag)
			append(out, name);
	return out;
}

std::string Wpa::groupCiphers(const uint64_t flags)
{
	if (flags == 0)
		return "None";
	std::string out;
	for (uint8_t type = 1; type <= LAST_CIPHER; type++)
		if (flags & groupCipherFlag(type))
			append(out, CIPHER_NAMES[type]);
	return out;
}

std::string Wpa::pairwiseCiphers(const uint64_t flags)
{
	if (flags == 0)
		return "None";
	std::string out;
	for (uint8_t type = 0; type <= LAST_CIPHER; type++)
		if (flags & pairwiseCipherFlag(type))
			append(out, CIPHER_NAMES[type]);
	return out;
}

std::string Wpa::akmSuites(const uint64_t flags)
{
	if (flags == 0)
		return "None";
	std::string out;
	for (uint8_t type = 0; type <= LAST_AKM; type++)
		if (flags & (1ULL << akmBit(type)))
			append(out, AKM_NAMES[type]);
	if (flags & F::AkmSaeExtKey)
		append(out, "SAE_EXT_KEY");
	if (flags & F::AkmFtSaeExtKey)
		append(out, "SAE_EXT_KEY_FT");
	return out;
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
	bool readSuiteList(ByteReader& r, Wpa::SuiteList& out)
	{
		const uint16_t count = r.le16();
		if (!r.ok() || r.remaining() < static_cast<size_t>(count) * 4)
			return false;
		for (uint16_t i = 0; i < count; i++)
			out.push_back(readSuite(r)); // past capacity: read and dropped
		return r.ok();
	}

	void writeSuiteList(ByteWriter& w, const Wpa::SuiteList& suites)
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
