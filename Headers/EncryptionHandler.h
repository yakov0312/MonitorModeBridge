//
// Created by yakov on 6/13/25.
//

#pragma once
#include <cstdint>

enum WIFI_SECURITY_TYPE_CIPHER : uint32_t
{
	// WPA (OUI 00:50:F2)
	WPA_TKIP = 0x0050F201,       // 00:50:F2:01
	WPA_WRAP = 0x0050F202,       // 00:50:F2:02 (Wireless Encryption Protocol)
	WPA_CCMP = 0x0050F204,       // 00:50:F2:04 (AES)

	// WPA2 (OUI 00:0F:AC)
	WPA2_NONE = 0x000FAC00,      // 00:0F:AC:00 (No encryption)
	WPA2_WEP40 = 0x000FAC01,     // 00:0F:AC:01 (WEP-40)
	WPA2_TKIP = 0x000FAC02,      // 00:0F:AC:02 (TKIP)
	WPA2_WRAP = 0x000FAC03,      // 00:0F:AC:03 (Wireless Encryption Protocol)
	WPA2_CCMP = 0x000FAC04,      // 00:0F:AC:04 (AES-CCMP)
	WPA2_WEP104 = 0x000FAC05,    // 00:0F:AC:05 (WEP-104)

	// WPA3
	WPA3_SUITE_B_128 = 0x000FAC06,   // 00:0F:AC:06 (GCMP-128, Suite B)
	WPA3_GCMP_256 = 0x000FAC08,      // 00:0F:AC:08 (GCMP-256)
};

class EncryptionHandler
{
public:
	bool setCipher(uint32_t cipher);

private:
	WIFI_SECURITY_TYPE_CIPHER m_cipherType;
};
