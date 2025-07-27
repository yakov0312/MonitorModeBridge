//
// Created by yakov on 6/16/25.
//
#include "Helper.h"
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
#include <vector>
#include <pcap/pcap.h>
#include "AdapterHandler.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/wireless.h>

#include "WifiDefenitions.h"

extern "C" {
#include "libwifi/gen/misc/radiotap.h"
#include "libwifi/core/misc/security.h"
#include "libwifi/core/radiotap/radiotap.h"
}
#include "openssl/evp.h"
#include "openssl/hmac.h"

constexpr const char* PTK_LABEL = "Pairwise key expansion";
constexpr uint8_t MAX_WRONG_PACKET = 10;

AdapterHandler& Helper::m_adapterHandler = AdapterHandler::getInstance();

void Helper::setChannel(uint8_t channel)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) throw std::runtime_error("Cannot init socket");

	iwreq wrq;
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.ifr_name, m_adapterHandler.getDeviceName().data(), IFNAMSIZ);
	wrq.u.freq.m = 2412 + 5 * (channel - 1);
	wrq.u.freq.e = 6;

	if (ioctl(sock, SIOCSIWFREQ, &wrq) != 0)
		throw std::runtime_error("Can't set channel");
	close(sock);
}

bool Helper::sendPackets(uint8_t numberOfPackets, const PacketHandlerFunc &packetHandler,
	std::vector<uint8_t> &packet, uint8_t channel)
{
	Helper::setChannel(channel); //ensure the channel is right

	uint8_t status = 0;
	PacketStatus packetHandlerStatus = PacketStatus::FAILED;
	pcap_pkthdr* header = {0};
	const u_char* rawResponse = nullptr;
	bool result = false;
	int wrongPacketCounter = 0;
	for (int i = 0; i < numberOfPackets; i++)
	{
		Helper::addRadioTap(packet, channel);
		//if the last packet was a random packet then dont send again but wait for the prev one
		if (wrongPacketCounter >= MAX_WRONG_PACKET &&
			pcap_sendpacket(m_adapterHandler.getDeviceHandle(), packet.data(), packet.size()) != 0)
			throw std::runtime_error("Cannot reach the specified network");
		if (wrongPacketCounter >= MAX_WRONG_PACKET)
			wrongPacketCounter = 0;

		status = pcap_next_ex(m_adapterHandler.getDeviceHandle(), &header, &rawResponse);
		Helper::checkStatus(status, i == numberOfPackets -1);
		if (status == 0)
		{
			packetHandlerStatus = PacketStatus::FAILED; //restore the status
			continue;
		}

		packetHandlerStatus = packetHandler(rawResponse, header->caplen);
		if (packetHandlerStatus == PacketStatus::SUCCESS)
			return true;
		if (packetHandlerStatus == PacketStatus::FAILED)
			throw std::runtime_error("AP returned an error");
		if (packetHandlerStatus == PacketStatus::WRONG_PACKET_TYPE) //the packet was a random packet
		{
			wrongPacketCounter++;
			i--;
		}
	}
	return false;
}

void Helper::checkStatus(uint8_t status, bool conditionResult)
{
	if (status == PCAP_ERROR)
		throw std::runtime_error(pcap_geterr(AdapterHandler::getInstance().getDeviceHandle()));
	else if (status != 1 && conditionResult)
		throw std::runtime_error("Cannot reach the specified network");
}

bool Helper::checkPacket(libwifi_frame *frame, const uint8_t *rawPacket, uint16_t packetSize, uint8_t subtype)
{
	if (libwifi_get_wifi_frame(frame, rawPacket, packetSize, IS_RADIOTAP) != 0)
		throw std::runtime_error("cannot parse the frame");
	else if (frame->frame_control.type == TYPE_MANAGEMENT && frame->frame_control.subtype == subtype)
		return true;
	return false;
}

void Helper::addRadioTap(std::vector<uint8_t>& packet, uint8_t channel)
{
	libwifi_radiotap_info info = {0};

	info.present =
		(1 << IEEE80211_RADIOTAP_TSFT)       |
		(1 << IEEE80211_RADIOTAP_FLAGS)      |
		(1 << IEEE80211_RADIOTAP_RATE)       |
		(1 << IEEE80211_RADIOTAP_CHANNEL);

	auto now = std::chrono::steady_clock::now();
	auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
	info.timestamp.timestamp = static_cast<uint64_t>(us);
	info.timestamp.accuracy = 0;
	info.timestamp.unit = 0;
	info.timestamp.flags = 0;

	info.flags = 0x00;
	info.rate_raw = Helper::m_adapterHandler.getDeviceRate();
	info.channel.freq = 2412 + 5 * (channel - 1);
	info.channel.flags = 0x00a0;

	char radiotapHeader[LIBWIFI_MAX_RADIOTAP_LEN] = {0};
	libwifi_create_radiotap(&info, radiotapHeader); //return an invalid size(12 instead of 18)
	size_t rtapLen = RADIOTAP_SIZE;
	//if there is already radiotap - remove it(done for loop usage, it can save up runtime and resources by not coping it each time)
	if (packet.size() >= 4 && (uint8_t)packet[0] == 0) {
		uint16_t existing_len = packet[2] | (packet[3] << 8);
		if (existing_len <= packet.size())
			packet.erase(packet.begin(), packet.begin() + existing_len);
	}
	radiotapHeader[2] = rtapLen & 0xff; //will write it always in little endian no matter what
	radiotapHeader[3] = (rtapLen >> 8) & 0xff;
	packet.insert(packet.begin(), radiotapHeader, radiotapHeader + rtapLen);
}

void Helper::getPmk(const std::string& password, uint8_t suite, const std::string& ssid, uint8_t* pmk)
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

void Helper::getPtkData(uint8_t* data, const uint8_t* nonce1, const uint8_t* nonce2, const uint8_t *mac1)
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

void Helper::getPtk(uint8_t* ptk, const uint8_t* pmk, const uint8_t* data, uint8_t suite)
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

void Helper::setMic(wpaAuthData &m2WpaData, const uint8_t *ptk, int akmSuite)
{
	memset(m2WpaData.keyInfo.mic, 0, sizeof(m2WpaData.keyInfo.mic));

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

	// Calculate HMAC over the whole m2WpaData struct
	if (!HMAC(md, kck, KCK_SIZE, reinterpret_cast<uint8_t*>(&m2WpaData), sizeof(m2WpaData), micOutput, &micLen))
		throw std::runtime_error("HMAC calculation failed");
	memcpy(m2WpaData.keyInfo.mic, micOutput, sizeof(m2WpaData.keyInfo.mic));
}

void Helper::decryptGtk(const uint8_t *ptk, uint8_t suite, const uint8_t *encryptedGtk, size_t encryptedLen,
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


int Helper::getKekLength(uint8_t suite)
{
	switch (suite) {
		case AKM_SUITE_PSK:
		case AKM_SUITE_PSK_SHA256: return 16;
		case AKM_PSK_SHA384: return 32;
		default: throw std::runtime_error("Unknown AKM suite for KEK length");
	}
}

void Helper::printPacketDebug(const u_char *packet, uint32_t length)
{
	std::cout << std::hex << std::setfill('0');
	for (size_t i = 0; i < length; ++i)
		std::cout << std::setw(2) << static_cast<unsigned>(packet[i]) << ' ';
}
