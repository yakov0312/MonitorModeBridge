#pragma once

#include "WifiDefenitions.h"

#include <string>

class AdapterHandler
{
public:
	~AdapterHandler();
	static AdapterHandler& getInstance();

	// Error related
	void resolveErrors();

	void setFilters() const;

	// Helper
	static void setDeviceToManaged();
	static void setDeviceToManaged(int sig);

	// Getters
	[[nodiscard]] const uint8_t* getDeviceMac() const;
	[[nodiscard]] std::string getDeviceName() const;
	[[nodiscard]] int getSocket() const;

private:
	AdapterHandler();

	// Initialize
	void initDevice();
	void initDeviceNetwork();

	// Instance
	static AdapterHandler m_instance;

	// Helpers
	static std::string findWirelessInterface();
	void closeSocket();
	void openRawSocket();
	static int getInterfaceIndex(const std::string& iface);
	static bool isMonitorMode(const std::string& iface);

	// Device
	int m_socket;
	uint8_t m_deviceMac[MAC_SIZE_BYTES];
	std::string m_deviceName;

};
