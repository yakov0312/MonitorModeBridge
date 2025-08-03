#pragma once
#include <string>

#include "WifiDefenitions.h"

class AdapterHandler
{
public:
	~AdapterHandler();
	static AdapterHandler& getInstance();

	//error related
	void resolveErrors();

	void setFilters();

	//helper
	static void setDeviceToManaged();
	static void setDeviceToManaged(int sig);

	//getters
	[[nodiscard]] const uint8_t* getDeviceMac() const;
	[[nodiscard]] std::string getDeviceName() const;
	[[nodiscard]] int getSocket() const;

private:
	AdapterHandler();

	//initialize
	void initDevice();
	void initDeviceNetwork();

	//instance
	static AdapterHandler m_instance;

	//helpers
	static std::string findWirelessInterface();
	void closeSocket();
	void openRawSocket();
	static int getInterfaceIndex(const std::string& iface);
	static bool isMonitorMode(const std::string& iface);

	//device
	int m_socket;
	uint8_t m_deviceMac[MAC_SIZE_BYTES];
	std::string m_deviceName;

};
