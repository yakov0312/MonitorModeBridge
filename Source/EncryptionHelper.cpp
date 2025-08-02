//
// Created by yakov on 6/16/25.
//
#include "EncryptionHelper.h"
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <pcap/pcap.h>
#include "AdapterHandler.h"

#include "WifiDefenitions.h"

extern "C" {
#include "libwifi/core/misc/security.h"
}
#include "openssl/evp.h"
#include "openssl/hmac.h"

constexpr const char* PTK_LABEL = "Pairwise key expansion";
constexpr uint8_t MAX_WRONG_PACKET = 10;

AdapterHandler& EncryptionHelper::m_adapterHandler = AdapterHandler::getInstance();

void EncryptionHelper::getPmk(const std::string& password, uint8_t suite, const std::string& ssid, uint8_t* pmk)
{
	if (pmk == nullptr)
		throw std::invalid_argument("invalid pmk ptr");

	if (suite == AKM_PSK_SHA384)
		PKCS5_PBKDF2_HMAC(password.data(), password.size(), reinterpret_cast<const u_char*>(ssid.c_str()),
			ssid.size(), PMK_ITERATIONS, EVP_sha384(), MAX_PMK_SIZE, pmk);
	else if (suite == AKM_SUITE_PSK_SHA256 || suite == AKM_SUITE_PSK)
		PKCS5_PBKDF2_HMAC(password.data(), password.size(),reinterpret_cast<const u_char*>(ssid.c_str()),
			ssid.size(),PMK_ITERATIONS,EVP_sha1(), PMK_SIZE_256, pmk);
	else
		throw std::invalid_argument("invalid suite");
}

void EncryptionHelper::getPtkData(uint8_t* data, const uint8_t* nonce1, const uint8_t* nonce2, const uint8_t *mac1)
{
	if (data == nullptr || nonce1 == nullptr || nonce2 == nullptr || mac1 == nullptr)
		throw std::invalid_argument("invalid pointers");
	//calculate data for ptk
	const uint8_t* mac2 = m_adapterHandler.getDeviceMac();
	if (memcmp(mac1, mac2, MAC_SIZE_BYTES) > 0)
		std::swap(mac1, mac2);

	if (memcmp(nonce1, nonce2, 32) > 0)
		std::swap(nonce1, nonce2);

	memcpy(data, mac1, MAC_SIZE_BYTES);
	memcpy(data + MAC_SIZE_BYTES, mac2,   MAC_SIZE_BYTES);
	memcpy(data + MAC_SIZE_BYTES * 2, nonce1, NONCE_SIZE);
	memcpy(data + MAC_SIZE_BYTES * 2 + NONCE_SIZE, nonce2, NONCE_SIZE);
}

void EncryptionHelper::getPtk(uint8_t* ptk, const uint8_t* pmk, const uint8_t* data, uint8_t suite)
{
	const EVP_MD* digest = nullptr;
	size_t pmkSize = 0;

	// Choose digest + pmk size based on suite
	switch (suite) {
		case AKM_SUITE_PSK:
			digest = EVP_sha1();
			pmkSize = 32;
			break;
		case AKM_SUITE_PSK_SHA256:
			digest = EVP_sha256();
			pmkSize = 32;
			break;
		case AKM_PSK_SHA384:
			digest = EVP_sha384();
			pmkSize = 48;
			break;
		default:
			throw std::runtime_error("Unsupported AKM suite for PTK derivation");
	}

	const size_t labelSize = strlen(PTK_LABEL);

	uint8_t seed[128]; // label + 0x00 + data + counter
	memcpy(seed, PTK_LABEL, labelSize);
	seed[labelSize] = 0x00;
	memcpy(seed + labelSize + 1, data, PTK_DATA_SIZE);
	size_t seedSize = labelSize + 1 + PTK_DATA_SIZE;

	uint8_t counter = 1;
	size_t offset = 0;

	while (offset < PTK_SIZE)
	{
		seed[seedSize] = counter;

		uint8_t digestOut[EVP_MAX_MD_SIZE];
		unsigned int digestSize = 0;

		if (!HMAC(digest, pmk, pmkSize, seed, seedSize + 1, digestOut, &digestSize))
			throw std::runtime_error("HMAC failed during PTK derivation");

		size_t copySize = std::min<size_t>(PTK_SIZE - offset, digestSize);
		memcpy(ptk + offset, digestOut, copySize);
		offset += copySize;
		++counter;
	}
}

void EncryptionHelper::setMic(EapolFrame &eapol, const uint8_t *ptk, int akmSuite)
{
	memset(eapol.keyDesc.mic, 0, MIC_SIZE);

	// Select hash function based on suite
	const EVP_MD* md = nullptr;
	if (akmSuite == AKM_SUITE_PSK)
		md = EVP_sha1();
	else if (akmSuite == AKM_SUITE_PSK_SHA256)
		md = EVP_sha256();
	else if (akmSuite == AKM_PSK_SHA384)
		md = EVP_sha384();
	else
		throw std::runtime_error("Unsupported AKM suite");

	// KCK is first 16 bytes of PTK
	const uint8_t* kck = ptk;
	unsigned int micLen = 0;
	uint8_t micOutput[EVP_MAX_MD_SIZE];

	uint8_t* startOffset = (uint8_t*)&eapol.eapolHeader;
	// Calculate HMAC over the whole m2WpaData struct
	if (!HMAC(md, kck, KCK_SIZE, startOffset, sizeof(EAPOLHeader) + sizeof(WPA2KeyDesc) + RSN_INFO_SIZE, micOutput, &micLen))
		throw std::runtime_error("HMAC calculation failed");
	memcpy(eapol.keyDesc.mic, micOutput, MIC_SIZE);
}

void EncryptionHelper::decryptGtk(const uint8_t *ptk, uint8_t suite, const uint8_t *encryptedGtk, size_t encryptedLen,
						uint8_t *decryptedGtk)
{
	int kekLen = getKekLength(suite);
	const uint8_t* kek = ptk + KCK_SIZE;

	const EVP_CIPHER* cipher = (kekLen == 16) ? EVP_aes_128_wrap() : EVP_aes_256_wrap();

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		throw std::runtime_error("EVP_CIPHER_CTX_new failed");

	if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, kek, nullptr))
		throw std::runtime_error("EVP_DecryptInit_ex failed");

	int outLen = 0;
	if (!EVP_DecryptUpdate(ctx, decryptedGtk, &outLen, encryptedGtk, encryptedLen))
		throw std::runtime_error("EVP_DecryptUpdate failed");

	int finalLen = 0;
	if (!EVP_DecryptFinal_ex(ctx, decryptedGtk + outLen, &finalLen))
		throw std::runtime_error("EVP_DecryptFinal_ex failed");

	EVP_CIPHER_CTX_free(ctx);
}


int EncryptionHelper::getKekLength(uint8_t suite)
{
	switch (suite) {
		case AKM_SUITE_PSK:
		case AKM_SUITE_PSK_SHA256: return 16;
		case AKM_PSK_SHA384: return 32;
		default: throw std::runtime_error("Unknown AKM suite for KEK length");
	}
}

void EncryptionHelper::printPacketDebug(const u_char *packet, uint32_t length)
{
	std::cout << std::hex << std::setfill('0');
	for (size_t i = 0; i < length; ++i)
		std::cout << std::setw(2) << static_cast<unsigned>(packet[i]) << ' ';
}
