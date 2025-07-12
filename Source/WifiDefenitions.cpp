//
// Created by yakov on 6/17/25.
//
#include "WifiDefenitions.h"

bool IS_RADIOTAP = false; //will be set later on

uint8_t RSN_WPA2[] =
{
	0x01, 0x00,                         // Version = 1
	0x00, 0x0F, 0xAC, 0x04,             // Group Cipher Suite: dynamically changing
	0x01, 0x00,                         // Pairwise Cipher Suite Count = 1
	0x00, 0x0F, 0xAC, 0x04,             // Pairwise Cipher Suite: AES (CCMP) if not supported drop connection
	0x01, 0x00,                         // AKM Suite Count = 1
	0x00, 0x0F, 0xAC, 0x00,             // AKM Suite: dynamically changing
	0x40, 0x00                          // RSN Capabilities: PMF supported
};

uint8_t RSN_WPA3[] =
{
	0x01, 0x00,                         // Version = 1
	0x00, 0x0F, 0xAC, 0x00,             // Group Cipher Suite: dynamically changing
	0x01, 0x00,                         // Pairwise Cipher Suite Count = 1
	0x00, 0x0F, 0xAC, 0x00,             // Pairwise Cipher Suite: dynamically changing
	0x01, 0x00,                         // AKM Suite Count = 1
	0x00, 0x0F, 0xAC, 0x00,             // AKM Suite: dynamically changing
	0x80, 0x00                          // RSN Capabilities: PMF required
};