// Created by yakov on 6/16/25.

#pragma once

#include <array>
#include <vector>

#include "../Constants/WifiDefenitions.h"

#include <pcap/pcap.h>

#include "openssl/types.h"

constexpr uint16_t TK_SIZE = 16;


enum PacketStatus
{
	SUCCESS,
	WRONG_PACKET_TYPE,
	INVALID_PACKET,
	FAILED
};

struct AKM
{
	std::vector<uint8_t> pmk;

	std::vector<uint8_t> ptk;
	uint8_t kckSize = 0;
	uint8_t kekSize = 0;
	uint8_t tkSize = TK_SIZE;
	uint8_t micSize = 0; // EAPOL-Key MIC length, set by the AKM (not the cipher)

	const EVP_MD* evpDigest;

	uint64_t suit;
};

struct Cipher
{
	uint64_t suit;
	uint8_t micSize;

	const EVP_CIPHER* evpCipher;
	std::vector<uint8_t> gtk;
	uint8_t gtkKeyId = 0;
	std::array<uint8_t, TK_SIZE> tk;
};

class CryptoManager
{
public:
	CryptoManager();

	void setSuit(uint64_t akmSuit, uint64_t cipherSuit);
	void setPmk(const std::string& password, const std::string& ssid);
	// aa = AP MAC, spa = our MAC
	void setPtk(const uint8_t* nonce1, const uint8_t* nonce2, const uint8_t* aa, const uint8_t* spa);
	// MIC over the EAPOL frame: eapolLength bytes starting at the EAPOL header
	void setMic(EapolFrame& eapol, size_t eapolLength) const;
	// Unwrap M3's encrypted key data (AES key wrap with the KEK) and take the
	// GTK out of its GTK KDE. Returns the GTK key id.
	uint8_t decryptGtk(const uint8_t* keyData, size_t keyDataLength);

	static void printPacketDebug(const u_char* packet, uint32_t length);

private:

	AKM m_akm;
	Cipher m_cipher;
};
