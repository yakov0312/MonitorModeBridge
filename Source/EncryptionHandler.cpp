//
// Created by yakov on 6/13/25.
//
#include "EncryptionHandler.h"

bool EncryptionHandler::setCipher(uint32_t cipher)
{
	bool result = false;
	switch (static_cast<WIFI_SECURITY_TYPE_CIPHER>(cipher)) {
		case WPA_TKIP:
		case WPA_WRAP:
		case WPA_CCMP:

		case WPA2_NONE:
		case WPA2_WEP40:
		case WPA2_TKIP:
		case WPA2_WRAP:
		case WPA2_CCMP:
		case WPA2_WEP104:

		case WPA3_SUITE_B_128:
		case WPA3_GCMP_256:
			// Valid cipher found
			result = true;
	}

	m_cipherType = static_cast<WIFI_SECURITY_TYPE_CIPHER>(cipher);

	return result;
}

