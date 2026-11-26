// C++ replacement for libwifi: WPA/RSN security information and EAPOL-Key.

#pragma once

#include "Common.h"
#include "Frame.h"
#include "Tags.h"

namespace Wifi
{

class Wpa
{
public:
	/*--------------*/
	/* SUITES / OUI */
	/*--------------*/

	using Oui = std::array<uint8_t, 3>;
	static constexpr Oui OUI_IEEE = {0x00, 0x0F, 0xAC};      // RSN suites
	static constexpr Oui OUI_MICROSOFT = {0x00, 0x50, 0xF2}; // WPA1/WMM/WPS vendor tags
	static constexpr Oui OUI_WFA = {0x50, 0x6F, 0x9A};

	// Microsoft vendor tag types
	static constexpr uint8_t MICROSOFT_TYPE_WPA = 1;
	static constexpr uint8_t MICROSOFT_TYPE_WMM = 2;
	static constexpr uint8_t MICROSOFT_TYPE_WPS = 4;

	enum class CipherSuite : uint8_t
	{
		UseGroup = 0,
		Wep40 = 1,
		Tkip = 2,
		Reserved = 3,
		Ccmp128 = 4,
		Wep104 = 5,
		BipCmac128 = 6,
		GroupNotAllowed = 7,
		Gcmp128 = 8,
		Gcmp256 = 9,
		Ccmp256 = 10,
		BipGmac128 = 11,
		BipGmac256 = 12,
		BipCmac256 = 13,
	};

	enum class AkmSuite : uint8_t
	{
		Reserved = 0,
		Ieee8021x = 1,
		Psk = 2,
		FtIeee8021x = 3,
		FtPsk = 4,
		Ieee8021xSha256 = 5,
		PskSha256 = 6,
		Tdls = 7,
		Sae = 8,
		FtSae = 9,
		ApPeerKey = 10,
		Ieee8021xSuiteBSha256 = 11,
		Ieee8021xSuiteBSha384 = 12,
		FtIeee8021xSha384 = 13,
		FilsSha256 = 14,
		FilsSha384 = 15,
		FtFilsSha256 = 16,
		FtFilsSha384 = 17,
		Owe = 18,
		FtPskSha384 = 19,
		PskSha384 = 20,
		Pasn = 21,
		SaeExtKey = 24,   // WPA3 with H2E/large groups (common on WiFi 7)
		FtSaeExtKey = 25,
	};

	struct Suite
	{
		Oui oui = OUI_IEEE;
		uint8_t type = 0;

		static Suite cipher(CipherSuite c) { return {OUI_IEEE, static_cast<uint8_t>(c)}; }
		static Suite akm(AkmSuite a) { return {OUI_IEEE, static_cast<uint8_t>(a)}; }
		[[nodiscard]] bool isIeee() const { return oui == OUI_IEEE; }
		[[nodiscard]] bool isMicrosoft() const { return oui == OUI_MICROSOFT; }
		bool operator==(const Suite&) const = default;
	};

	/*----------------------------------------------*/
	/* SECURITY FLAGS (same bit layout as libwifi's  */
	/* libwifi_bss.encryption_info)                  */
	/*----------------------------------------------*/

	struct Flag
	{
		static constexpr uint64_t Wep = 1ULL << 1;
		static constexpr uint64_t Wpa = 1ULL << 2;
		static constexpr uint64_t Wpa2 = 1ULL << 3;
		static constexpr uint64_t Wpa3 = 1ULL << 4;

		static constexpr uint64_t GroupWep40 = 1ULL << 5;
		static constexpr uint64_t GroupTkip = 1ULL << 6;
		static constexpr uint64_t GroupReserved = 1ULL << 7;
		static constexpr uint64_t GroupCcmp128 = 1ULL << 8;
		static constexpr uint64_t GroupWep104 = 1ULL << 9;
		static constexpr uint64_t GroupBipCmac128 = 1ULL << 10;
		static constexpr uint64_t GroupNotAllowed = 1ULL << 11;
		static constexpr uint64_t GroupGcmp128 = 1ULL << 12;
		static constexpr uint64_t GroupGcmp256 = 1ULL << 13;
		static constexpr uint64_t GroupCcmp256 = 1ULL << 14;
		static constexpr uint64_t GroupBipGmac128 = 1ULL << 15;
		static constexpr uint64_t GroupBipGmac256 = 1ULL << 16;
		static constexpr uint64_t GroupBipCmac256 = 1ULL << 17;

		static constexpr uint64_t PairwiseUseGroup = 1ULL << 18;
		static constexpr uint64_t PairwiseWep40 = 1ULL << 19;
		static constexpr uint64_t PairwiseTkip = 1ULL << 20;
		static constexpr uint64_t PairwiseReserved = 1ULL << 21;
		static constexpr uint64_t PairwiseCcmp128 = 1ULL << 22;
		static constexpr uint64_t PairwiseWep104 = 1ULL << 23;
		static constexpr uint64_t PairwiseBipCmac128 = 1ULL << 24;
		static constexpr uint64_t PairwiseNotAllowed = 1ULL << 25;
		static constexpr uint64_t PairwiseGcmp128 = 1ULL << 26;
		static constexpr uint64_t PairwiseGcmp256 = 1ULL << 27;
		static constexpr uint64_t PairwiseCcmp256 = 1ULL << 28;
		static constexpr uint64_t PairwiseBipGmac128 = 1ULL << 29;
		static constexpr uint64_t PairwiseBipGmac256 = 1ULL << 30;
		static constexpr uint64_t PairwiseBipCmac256 = 1ULL << 31;

		static constexpr uint64_t AkmReserved = 1ULL << 32;
		static constexpr uint64_t Akm8021x = 1ULL << 33;
		static constexpr uint64_t AkmPsk = 1ULL << 34;
		static constexpr uint64_t AkmFt8021x = 1ULL << 35;
		static constexpr uint64_t AkmFtPsk = 1ULL << 36;
		static constexpr uint64_t Akm8021xSha256 = 1ULL << 37;
		// bit 38 is unused, as in libwifi
		static constexpr uint64_t AkmPskSha256 = 1ULL << 39;
		static constexpr uint64_t AkmTdls = 1ULL << 40;
		static constexpr uint64_t AkmSae = 1ULL << 41;
		static constexpr uint64_t AkmFtSae = 1ULL << 42;
		static constexpr uint64_t AkmApPeerKey = 1ULL << 43;
		static constexpr uint64_t Akm8021xSuiteBSha256 = 1ULL << 44;
		static constexpr uint64_t Akm8021xSuiteBSha384 = 1ULL << 45;
		static constexpr uint64_t AkmFt8021xSha384 = 1ULL << 46;
		static constexpr uint64_t AkmFilsSha256 = 1ULL << 47;
		static constexpr uint64_t AkmFilsSha384 = 1ULL << 48;
		static constexpr uint64_t AkmFtFilsSha256 = 1ULL << 49;
		static constexpr uint64_t AkmFtFilsSha384 = 1ULL << 50;
		static constexpr uint64_t AkmOwe = 1ULL << 51;
		static constexpr uint64_t AkmFtPskSha384 = 1ULL << 52;
		static constexpr uint64_t AkmPskSha384 = 1ULL << 53;

		static constexpr uint64_t AuthOpen = 1ULL << 54;
		static constexpr uint64_t AuthSharedKey = 1ULL << 55;
		static constexpr uint64_t AuthFastBss = 1ULL << 56;
		static constexpr uint64_t AuthSae = 1ULL << 57;
		static constexpr uint64_t AuthVendor = 1ULL << 58;

		// Not in libwifi
		static constexpr uint64_t AkmSaeExtKey = 1ULL << 59;
		static constexpr uint64_t AkmFtSaeExtKey = 1ULL << 60;
	};

	// RSN Capabilities field
	struct RsnCapability
	{
		static constexpr uint16_t Preauth = 1 << 0;
		static constexpr uint16_t NoPairwise = 1 << 1;
		static constexpr uint16_t PtksaReplayCounter = 1 << 2 | 1 << 3;
		static constexpr uint16_t GtksaReplayCounter = 1 << 4 | 1 << 5;
		static constexpr uint16_t MfpRequired = 1 << 6;
		static constexpr uint16_t MfpCapable = 1 << 7;
		static constexpr uint16_t JointMultiBandRsna = 1 << 8;
		static constexpr uint16_t PeerKey = 1 << 9;
		static constexpr uint16_t SppAmsduCapable = 1 << 10;
		static constexpr uint16_t SppAmsduRequired = 1 << 11;
		static constexpr uint16_t Pbac = 1 << 12;
		static constexpr uint16_t ExtendedKeyId = 1 << 13;
		static constexpr uint16_t Ocvc = 1 << 14;
	};

	// Flag bit for one suite value (0 if libwifi had no bit for it)
	static uint64_t groupCipherFlag(uint8_t suiteType);
	static uint64_t pairwiseCipherFlag(uint8_t suiteType);
	// Also sets the WPA2 or WPA3 bit the AKM implies
	static uint64_t akmFlag(uint8_t suiteType);

	// Comma separated names, as libwifi_get_security_type & co. printed them
	static std::string securityTypes(uint64_t flags);
	static std::string groupCiphers(uint64_t flags);
	static std::string pairwiseCiphers(uint64_t flags);
	static std::string akmSuites(uint64_t flags);

	/*----------------------------*/
	/* RSN ELEMENT (TAG 48) / WPA */
	/*----------------------------*/

	using Pmkid = std::array<uint8_t, 16>;

	struct RsnInfo
	{
		uint16_t version = 1;
		Suite groupCipher = Suite::cipher(CipherSuite::Ccmp128);
		std::vector<Suite> pairwiseCiphers;
		std::vector<Suite> akmSuites;
		uint16_t capabilities = 0; // RsnCapability bits
		std::vector<Pmkid> pmkids;
		std::optional<Suite> groupManagementCipher;

		// A typical station RSN element: one pairwise cipher, one AKM
		static RsnInfo create(CipherSuite group, CipherSuite pairwise, AkmSuite akm, uint16_t capabilities = 0);

		// Tag body (without the 2-byte tag header). Everything after the
		// group cipher is optional on the air, so only those are required.
		static std::optional<RsnInfo> parse(std::span<const uint8_t> body);
		// Tag body, ready for Tags::add(TagNumber::Rsn, ...). Trailing
		// optional fields are only written when used.
		[[nodiscard]] std::vector<uint8_t> build() const;
		[[nodiscard]] uint64_t flags() const;

		[[nodiscard]] bool hasPairwise(CipherSuite c) const;
		[[nodiscard]] bool hasAkm(AkmSuite a) const;
	};

	// WPA1 vendor tag (00:50:F2 type 1). Same layout as RSN up to the AKMs.
	struct WpaInfo
	{
		uint16_t version = 1;
		Suite multicastCipher;
		std::vector<Suite> unicastCiphers;
		std::vector<Suite> akmSuites;

		// Body after the OUI and the vendor type byte
		static std::optional<WpaInfo> parse(std::span<const uint8_t> body);
		[[nodiscard]] uint64_t flags() const;
	};

	/*-------*/
	/* EAPOL */
	/*-------*/

	static constexpr uint16_t EAPOL_ETHER_TYPE = 0x888E;
	// 802.2 LLC + SNAP header in front of EAPOL in an 802.11 data frame
	static constexpr std::array<uint8_t, 8> LLC_SNAP_EAPOL = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
	static constexpr size_t EAPOL_HEADER_LENGTH = 4;
	static constexpr size_t NONCE_LENGTH = 32;
	static constexpr size_t DEFAULT_MIC_LENGTH = 16; // 24 for the SHA-384 AKMs

	enum class EapolType : uint8_t
	{
		EapPacket = 0,
		Start = 1,
		Logoff = 2,
		Key = 3,
		EncapsulatedAsfAlert = 4,
	};

	enum class KeyDescriptor : uint8_t
	{
		Rc4 = 1,
		Rsn = 2, // WPA2/WPA3
		Wpa = 254,
	};

	// Key Information field (host order; big-endian on the air)
	struct KeyInfo
	{
		static constexpr uint16_t VersionMask = 0x0007;
		static constexpr uint16_t VersionAkmDefined = 0;
		static constexpr uint16_t VersionHmacMd5Rc4 = 1;
		static constexpr uint16_t VersionHmacSha1Aes = 2;
		static constexpr uint16_t VersionAesCmac = 3;
		static constexpr uint16_t Pairwise = 0x0008;
		static constexpr uint16_t Install = 0x0040;
		static constexpr uint16_t Ack = 0x0080;
		static constexpr uint16_t Mic = 0x0100;
		static constexpr uint16_t Secure = 0x0200;
		static constexpr uint16_t Error = 0x0400;
		static constexpr uint16_t Request = 0x0800;
		static constexpr uint16_t EncryptedKeyData = 0x1000;
		static constexpr uint16_t Smk = 0x2000;
	};

	// Values match libwifi's HANDSHAKE_M1.. so old comparisons still work
	enum class HandshakeMessage : uint8_t
	{
		M1 = 1,
		M2 = 2,
		M3 = 4,
		M4 = 8,
		Invalid = 16,
		GroupM1 = 32,
		GroupM2 = 64,
	};
	static const char* messageName(HandshakeMessage message);

	// EAPOL-Key frame: EAPOL header + key descriptor + key data
	struct EapolKey
	{
		uint8_t version = 2;
		EapolType type = EapolType::Key;
		KeyDescriptor descriptor = KeyDescriptor::Rsn;
		uint16_t keyInformation = 0; // KeyInfo bits
		uint16_t keyLength = 0;
		uint64_t replayCounter = 0;
		std::array<uint8_t, NONCE_LENGTH> nonce{};
		std::array<uint8_t, 16> iv{};
		std::array<uint8_t, 8> rsc{};
		std::array<uint8_t, 8> id{};
		std::vector<uint8_t> mic = std::vector<uint8_t>(DEFAULT_MIC_LENGTH, 0);
		std::vector<uint8_t> keyData;

		// From the EAPOL header on (after LLC/SNAP)
		static std::optional<EapolKey> parse(std::span<const uint8_t> eapol, size_t micLength = DEFAULT_MIC_LENGTH);
		// From a received data frame (checks LLC/SNAP and the EAPOL type)
		static std::optional<EapolKey> parse(const Frame& frame, size_t micLength = DEFAULT_MIC_LENGTH);

		[[nodiscard]] bool has(uint16_t keyInfoBit) const { return (keyInformation & keyInfoBit) != 0; }
		[[nodiscard]] uint16_t descriptorVersion() const { return keyInformation & KeyInfo::VersionMask; }
		// Which 4-way / group handshake message this is, from the key info bits
		[[nodiscard]] HandshakeMessage message() const;

		// EAPOL bytes: header + descriptor + key data. To add a MIC, build
		// with the MIC zeroed, compute the MIC over the result, put it in
		// mic and build again (or patch at micOffset()).
		[[nodiscard]] std::vector<uint8_t> build() const;
		[[nodiscard]] size_t length() const;
		// Offset of the MIC inside build()
		[[nodiscard]] static constexpr size_t micOffset() { return EAPOL_HEADER_LENGTH + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8; }

		// Complete 802.11 data frame (station -> AP, ToDS) carrying this key:
		// MAC header + LLC/SNAP + build()
		[[nodiscard]] std::vector<uint8_t> buildDataFrame(const MacAddress& bssid, const MacAddress& station,
			uint16_t sequence) const;
	};

	// Data frame that carries EAPOL (libwifi_check_wpa_handshake)
	static bool isEapol(const Frame& frame);
	// libwifi_check_wpa_message
	static HandshakeMessage message(const Frame& frame);
};

} // namespace Wifi
