// Created by yakov on 6/16/25.

#include "CryptoManager.h"
#include "../Constants/WifiDefenitions.h"

#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pcap/pcap.h>

extern "C" {
  #include <libwifi/core/misc/security.h>
}

// WPA2-PSK (AKM 2), IEEE 802.11-2020 12.7.1.2 / 12.7.2
constexpr uint16_t AKM_PSK_PMK_SIZE = 32;
constexpr uint16_t AKM_PSK_KCK_SIZE = 16;
constexpr uint16_t AKM_PSK_KEK_SIZE = 16;
constexpr uint16_t AKM_PSK_MIC_SIZE = 16; // HMAC-SHA1-128

// Temporal key sizes
constexpr uint16_t TK128_SIZE = 16; // CCMP-128 / GCMP-128
constexpr uint16_t TK256_SIZE = 32; // CCMP-256 / GCMP-256

//CMP-128
constexpr uint16_t CMP128_GTK_SIZE = 16;

//CMP-256
constexpr uint16_t CMP256_GTK_SIZE = 32;

//PTK
constexpr uint8_t PTK_DATA_SIZE = 76;
constexpr auto PTK_LABEL = "Pairwise key expansion";


CryptoManager::CryptoManager() : m_akm(), m_cipher()
{
}

void CryptoManager::setSuit(const uint64_t akmSuit, const uint64_t cipherSuit)
{
	// Only AKM 2 (PSK with HMAC-SHA1) is implemented. AKM 6 (PSK-SHA256) needs
	// the SHA256 KDF and an AES-CMAC MIC, AKM 20 (PSK-SHA384) HMAC-SHA384-192:
	// refuse them instead of producing keys the AP will reject.
	if (akmSuit != AKM_SUITE_PSK)
		throw std::invalid_argument("AKM " + std::to_string(akmSuit) + " is not supported yet (only WPA2-PSK, AKM 2)");

	m_akm.pmk.resize(AKM_PSK_PMK_SIZE);
	m_akm.kckSize = AKM_PSK_KCK_SIZE;
	m_akm.kekSize = AKM_PSK_KEK_SIZE;
	m_akm.micSize = AKM_PSK_MIC_SIZE;
	m_akm.evpDigest = EVP_sha1();

	if (cipherSuit == CIPHER_SUITE_GCMP128 || cipherSuit == CIPHER_SUITE_CCMP128)
	{
		m_akm.tkSize = TK128_SIZE;
		m_cipher.gtk.resize(CMP128_GTK_SIZE);
		m_cipher.evpCipher = (cipherSuit == CIPHER_SUITE_GCMP128) ? EVP_aes_128_gcm() : EVP_aes_128_ccm();
	}
	else if (cipherSuit == CIPHER_SUITE_GCMP256 || cipherSuit == CIPHER_SUITE_CCMP256)
	{
		m_akm.tkSize = TK256_SIZE;
		m_cipher.gtk.resize(CMP256_GTK_SIZE);
		m_cipher.evpCipher = (cipherSuit == CIPHER_SUITE_GCMP256) ? EVP_aes_256_gcm() : EVP_aes_256_ccm();
	}
	else
		throw std::invalid_argument("Suit not supported");

	// PTK = KCK || KEK || TK
	m_akm.ptk.resize(m_akm.kckSize + m_akm.kekSize + m_akm.tkSize);

	m_cipher.suit = cipherSuit;
	m_akm.suit = akmSuit;
}

void CryptoManager::setPmk(const std::string& password, const std::string& ssid)
{
	if (m_akm.suit == 0)
		throw std::invalid_argument("Invalid suite");

	// Passphrase -> PSK is always PBKDF2-HMAC-SHA1, 4096 rounds, 256 bits
	// (802.11-2020 J.4), whatever hash the AKM uses later.
	if (!PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
			reinterpret_cast<const u_char*>(ssid.c_str()), static_cast<int>(ssid.size()),
			PMK_ITERATIONS, EVP_sha1(), static_cast<int>(m_akm.pmk.size()), m_akm.pmk.data()))
		throw std::runtime_error("PBKDF2 failed");
}

void CryptoManager::setPtk(const uint8_t* nonce1, const uint8_t* nonce2, const uint8_t* aa, const uint8_t* spa)
{
	if (!nonce1 || !nonce2 || !aa || !spa)
        throw std::invalid_argument("Invalid pointers");

	if (m_akm.suit == 0)
		throw std::invalid_argument("Invalid suite");

	const uint8_t* pmk = m_akm.pmk.data();
	uint8_t* ptk = m_akm.ptk.data();

    const uint8_t* mac1 = aa;
    const uint8_t* mac2 = spa;

    // Ensure deterministic ordering (both sides must match exactly)
    if (memcmp(mac1, mac2, MAC_SIZE_BYTES) > 0)
        std::swap(mac1, mac2);

    // Ensure deterministic nonce ordering (ANonce / SNonce)
    if (memcmp(nonce1, nonce2, NONCE_SIZE) > 0)
        std::swap(nonce1, nonce2);

    // Build PTK input seed
    // PTK input = MACs + nonces (ordered)
    uint8_t ptkData[PTK_DATA_SIZE];

    memcpy(ptkData, mac1, MAC_SIZE_BYTES);
    memcpy(ptkData + MAC_SIZE_BYTES, mac2, MAC_SIZE_BYTES);

    memcpy(ptkData + MAC_SIZE_BYTES * 2, nonce1, NONCE_SIZE);
    memcpy(ptkData + MAC_SIZE_BYTES * 2 + NONCE_SIZE, nonce2, NONCE_SIZE);

    // WPA PRF label ("Pairwise key expansion")
    const size_t labelSize = strlen(PTK_LABEL);

    uint8_t seed[128];
    memcpy(seed, PTK_LABEL, labelSize);

    // Null separator required by WPA PRF
    seed[labelSize] = 0x00;

    // Append PTK input data
    memcpy(seed + labelSize + 1, ptkData, PTK_DATA_SIZE);

    const size_t seedSize = labelSize + 1 + PTK_DATA_SIZE;

    // PRF-n (802.11-2020 12.7.1.2): HMAC-SHA1(PMK, label || 0x00 || data || i)
    // with i counting from 0
    uint8_t counter = 0;
    size_t offset = 0;

    while (offset < m_akm.ptk.size())
    {
        // Append counter at end of seed (KDF iteration index)
        seed[seedSize] = counter;

        uint8_t digestOut[EVP_MAX_MD_SIZE];
        unsigned int digestSize = 0;

        // HMAC(PMK, seed || counter)
    	const auto res = HMAC(m_akm.evpDigest, pmk, m_akm.pmk.size(), seed, seedSize + 1, digestOut, &digestSize);
        if (!res)
            throw std::runtime_error("HMAC failed during PTK derivation");

        // Copy required bytes into PTK buffer
        const size_t copySize = std::min<size_t>(m_akm.ptk.size() - offset, digestSize);

        memcpy(ptk + offset, digestOut, copySize);

        offset += copySize;
        ++counter;
    }
}

void CryptoManager::setMic(EapolFrame& eapol, const size_t eapolLength) const
{
	if (m_akm.suit == 0)
		throw std::invalid_argument("Invalid suite");

	// The MIC is computed with the MIC field set to zero
	memset(eapol.keyDesc.mic, 0, sizeof(eapol.keyDesc.mic));

	// KCK is the first kckSize bytes of the PTK
	const uint8_t* kck = m_akm.ptk.data();
	unsigned int micLen = 0;
	uint8_t micOutput[EVP_MAX_MD_SIZE];

	// HMAC over the EAPOL frame: header + key descriptor (incl. key data)
	const auto* startOffset = reinterpret_cast<uint8_t*>(&eapol.eapolHeader);
	if (!HMAC(m_akm.evpDigest, kck, m_akm.kckSize, startOffset, eapolLength, micOutput, &micLen))
		throw std::runtime_error("HMAC calculation failed");

	// HMAC-SHA1 gives 20 bytes; the MIC field takes the first 16
	memcpy(eapol.keyDesc.mic, micOutput, m_akm.micSize);
}

uint8_t CryptoManager::decryptGtk(const uint8_t* keyData, const size_t keyDataLength)
{
	// AES key wrap (RFC 3394): input is n*8 bytes incl. the 8-byte integrity
	// block, output 8 bytes shorter. The integrity check covers the whole
	// block, so all of it must be unwrapped at once.
	if (!keyData || keyDataLength < 16 || keyDataLength % 8 != 0)
		throw std::runtime_error("M3: invalid encrypted key data length " + std::to_string(keyDataLength));

	const uint8_t* kek = m_akm.ptk.data() + m_akm.kckSize;
	const EVP_CIPHER* cipher = (m_akm.kekSize == 16) ? EVP_aes_128_wrap() : EVP_aes_256_wrap();

	std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!ctx)
		throw std::runtime_error("EVP_CIPHER_CTX_new failed");

	// OpenSSL refuses wrap modes through EVP unless explicitly allowed
	EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	if (!EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, kek, nullptr))
		throw std::runtime_error("EVP_DecryptInit_ex failed");

	std::vector<uint8_t> plain(keyDataLength); // unwrap writes keyDataLength - 8
	int outLen = 0;
	if (!EVP_DecryptUpdate(ctx.get(), plain.data(), &outLen, keyData, static_cast<int>(keyDataLength)))
		throw std::runtime_error("M3: key data unwrap failed (wrong KEK?)");

	int finalLen = 0;
	if (!EVP_DecryptFinal_ex(ctx.get(), plain.data() + outLen, &finalLen))
		throw std::runtime_error("M3: key data unwrap failed (wrong KEK?)");
	plain.resize(outLen + finalLen);

	// Walk the elements: RSN IE (0x30), KDEs (0xdd len OUI type data...),
	// padding (0xdd followed by zeros). GTK KDE: 0xdd len 00-0f-ac 01
	// keyid/tx reserved GTK.
	constexpr uint8_t KDE_TYPE = 0xdd;
	constexpr uint8_t GTK_KDE_HEADER[] = {0x00, 0x0f, 0xac, 0x01};
	constexpr size_t GTK_KDE_PREFIX = sizeof(GTK_KDE_HEADER) + 2; // OUI+type, keyid/tx, reserved

	for (size_t i = 0; i + 2 <= plain.size();)
	{
		const uint8_t type = plain[i];
		const uint8_t len = plain[i + 1];

		if (type == KDE_TYPE && len == 0)
			break; // padding
		if (i + 2 + len > plain.size())
			break;

		const uint8_t* body = plain.data() + i + 2;
		if (type == KDE_TYPE && len > GTK_KDE_PREFIX &&
			memcmp(body, GTK_KDE_HEADER, sizeof(GTK_KDE_HEADER)) == 0)
		{
			const size_t gtkLen = len - GTK_KDE_PREFIX;
			m_cipher.gtk.assign(body + GTK_KDE_PREFIX, body + GTK_KDE_PREFIX + gtkLen);
			m_cipher.gtkKeyId = body[sizeof(GTK_KDE_HEADER)] & 0x03;
			return m_cipher.gtkKeyId;
		}

		i += 2 + len;
	}

	throw std::runtime_error("M3: no GTK KDE in key data");
}

void CryptoManager::printPacketDebug(const u_char* packet, const uint32_t length)
{
	std::cout << std::hex << std::setfill('0');

	for (size_t i = 0; i < length; ++i)
		std::cout << std::setw(2) << static_cast<unsigned>(packet[i]) << ' ';
}
