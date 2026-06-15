#pragma once

#include "../Constants/WifiDefenitions.h"

#include <string>

class InterfaceHandler
{
public:
	~InterfaceHandler();
	static InterfaceHandler& getInstance();

	// Error related
	void resolveErrors();

	void setFilters() const;

	// Helper
	static void setInterfaceToManaged();
	static void setInterfaceToManaged(int sig);

	// Getters
	[[nodiscard]] const uint8_t* getInterfaceMac() const;
	[[nodiscard]] std::string getInterfaceName() const;
	[[nodiscard]] int getSocket() const;

private:
	InterfaceHandler();

	// Initialize
	void initializeInterface();

	// Instance
	static InterfaceHandler m_instance;

	// Helpers
	static std::string findWirelessInterface();
	void closeSocket();
	void openRawSocket();
	static int getInterfaceIndex(const std::string& iface);
	static bool isMonitorMode(const std::string& iface);

	// Device
	int m_socket;
	uint8_t m_interfaceMac[MAC_SIZE_BYTES];
	std::string m_interfaceName;
};
