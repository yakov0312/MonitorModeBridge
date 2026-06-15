// Created by yakov on 6/16/25.

#pragma once

#include <array>
#include <vector>

#include "../Constants/WifiDefenitions.h"
#include "../Interface/InterfaceHandler.h"

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
	uint8_t kckSize;
	uint8_t kekSize;
	uint8_t tkSize = TK_SIZE;

	const EVP_MD* evpDigest;

	uint64_t suit;
};

struct Cipher
{
	uint64_t suit;
	uint8_t micSize;

	const EVP_CIPHER* evpCipher;
	std::vector<uint8_t> gtk;
	std::array<uint8_t, TK_SIZE> tk;
};

class CryptoManager
{
public:
	CryptoManager();

	void setSuit(uint64_t akmSuit, uint64_t cipherSuit);
	void setPmk(const std::string& password, const std::string& ssid);
	void setPtk(const uint8_t* nonce1, const uint8_t* nonce2, const uint8_t* mac1);
	void setMic(EapolFrame& eapol) const;
	void decryptGtk(const uint8_t* encryptedGtk);

	static void printPacketDebug(const u_char* packet, uint32_t length);

private:
	static InterfaceHandler& m_adapterHandler;

	AKM m_akm;
	Cipher m_cipher;
};
