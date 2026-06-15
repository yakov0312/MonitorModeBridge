// Created by yakov on 6/16/25.

#include "CryptoManager.h"
#include "../Constants/WifiDefenitions.h"
#include "../Interface/InterfaceHandler.h"

#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pcap/pcap.h>

extern "C" {
  #include <libwifi/core/misc/security.h>
}

//SHA256
constexpr uint16_t AKM_SHA256_PTK_SIZE = 48;
constexpr uint16_t AKM_SHA256_KCK_SIZE = 16;
constexpr uint16_t AKM_SHA256_KEK_SIZE = 16;

constexpr uint16_t AKM_SHA256_PMK_SIZE = 32;

//SHA 384
constexpr uint16_t AKM_SHA384_PTK_SIZE = 48;
constexpr uint16_t AKM_SHA384_KCK_SIZE = 24;
constexpr uint16_t AKM_SHA384_KEK_SIZE = 32;

constexpr uint16_t AKM_SHA384_PMK_SIZE = 72;

//CMP-128
constexpr uint16_t CMP128_GTK_SIZE = 16;
constexpr uint16_t CMP128_MIC_SIZE = 8;

//CMP-256
constexpr uint16_t CMP256_GTK_SIZE = 32;
constexpr uint16_t CMP256_MIC_SIZE = 8;

//PTK
constexpr uint8_t PTK_DATA_SIZE = 76;
constexpr auto PTK_LABEL = "Pairwise key expansion";

InterfaceHandler& CryptoManager::m_adapterHandler = InterfaceHandler::getInstance();

CryptoManager::CryptoManager() : m_akm(), m_cipher()
{
}

void CryptoManager::setSuit(const uint64_t akmSuit, const uint64_t cipherSuit)
{
	if (akmSuit == AKM_SUITE_PSK || akmSuit == AKM_SUITE_PSK_SHA256)
	{
		m_akm.pmk.resize(AKM_SHA256_PMK_SIZE);
		m_akm.ptk.resize(AKM_SHA256_PTK_SIZE);
		m_akm.evpDigest = (akmSuit == AKM_SUITE_PSK_SHA256) ? EVP_sha256() : EVP_sha1();
	}
	else if (akmSuit == AKM_PSK_SHA384)
	{
		m_akm.pmk.resize(AKM_SHA384_PMK_SIZE);
		m_akm.ptk.resize(AKM_SHA384_PTK_SIZE);
		m_akm.evpDigest = EVP_sha384();
	}
	else
		throw std::invalid_argument("Suit not supported"); // SAE & OWE

	if (cipherSuit == CIPHER_SUITE_GCMP128 || cipherSuit == CIPHER_SUITE_CCMP128)
	{
		m_cipher.micSize = CMP128_MIC_SIZE;
		m_cipher.gtk.resize(CMP128_GTK_SIZE);
		m_cipher.evpCipher = (cipherSuit == CIPHER_SUITE_GCMP128) ? EVP_aes_128_gcm() : EVP_aes_128_ccm();
	}
	else if (cipherSuit == CIPHER_SUITE_GCMP256 || cipherSuit == CIPHER_SUITE_CCMP256)
	{
		m_cipher.micSize = CMP256_MIC_SIZE;
		m_cipher.gtk.resize(CMP256_GTK_SIZE);
		m_cipher.evpCipher = (cipherSuit == CIPHER_SUITE_GCMP256) ? EVP_aes_256_gcm() : EVP_aes_256_ccm();
	}
	else
		throw std::invalid_argument("Suit not supported");

	m_cipher.suit = cipherSuit;
	m_akm.suit = akmSuit;
}

void CryptoManager::setPmk(const std::string& password, const std::string& ssid)
{
	if (m_akm.suit == 0)
		throw std::invalid_argument("Invalid suite");

	PKCS5_PBKDF2_HMAC(password.data(), password.size(), reinterpret_cast<const u_char*>(ssid.c_str()),
		   ssid.size(), PMK_ITERATIONS, m_akm.evpDigest, m_akm.pmk.size(), m_akm.pmk.data());
}

void CryptoManager::setPtk(const uint8_t* nonce1, const uint8_t* nonce2, const uint8_t* mac1)
{
	if (!nonce1 || !nonce2 || !mac1)
        throw std::invalid_argument("Invalid pointers");

	if (m_akm.suit == 0)
		throw std::invalid_argument("Invalid suite");

	const uint8_t* pmk = m_akm.pmk.data();
	uint8_t* ptk = m_akm.ptk.data();

    // Get both MAC addresses
    const uint8_t* mac2 = m_adapterHandler.getInterfaceMac();

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

    // Expand key material using iterative HMAC
    uint8_t counter = 1;
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

void CryptoManager::setMic(EapolFrame& eapol) const
{
	if (m_akm.suit == 0)
		throw std::invalid_argument("Invalid suite");

	memset(eapol.keyDesc.mic, 0, m_cipher.micSize);

	// KCK is first 16 bytes of PTK
	const uint8_t* kck = m_akm.ptk.data();
	unsigned int micLen = 0;
	uint8_t micOutput[EVP_MAX_MD_SIZE];

	const auto* startOffset = reinterpret_cast<uint8_t*>(&eapol.eapolHeader);

	// Calculate HMAC over the whole m2WpaData struct
	if (!HMAC(m_akm.evpDigest, kck, m_akm.kckSize, startOffset, sizeof(EAPOLHeader) + sizeof(WPA2KeyDesc), micOutput, &micLen))
		throw std::runtime_error("HMAC calculation failed");

	memcpy(eapol.keyDesc.mic, micOutput, m_cipher.micSize);
}

void CryptoManager::decryptGtk(const uint8_t* encryptedGtk)
{
	const uint8_t* kek = m_akm.ptk.data() + m_akm.kckSize;
	const uint16_t encryptedGtkLen = ((m_cipher.gtk.size() / 8) + 1) * 8;

	// The wrapping key size determines the algorithm variant
	const EVP_CIPHER* cipher = (m_akm.kekSize == 16) ? EVP_aes_128_wrap() : EVP_aes_256_wrap();

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		throw std::runtime_error("EVP_CIPHER_CTX_new failed");

	if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, kek, nullptr))
		throw std::runtime_error("EVP_DecryptInit_ex failed");

	int outLen = 0;
	if (!EVP_DecryptUpdate(ctx, m_cipher.gtk.data(), &outLen, encryptedGtk, encryptedGtkLen))
		throw std::runtime_error("EVP_DecryptUpdate failed");

	int finalLen = 0;
	if (!EVP_DecryptFinal_ex(ctx, m_cipher.gtk.data() + outLen, &finalLen))
		throw std::runtime_error("EVP_DecryptFinal_ex failed");

	EVP_CIPHER_CTX_free(ctx);
}

void CryptoManager::printPacketDebug(const u_char* packet, const uint32_t length)
{
	std::cout << std::hex << std::setfill('0');

	for (size_t i = 0; i < length; ++i)
		std::cout << std::setw(2) << static_cast<unsigned>(packet[i]) << ' ';
}
