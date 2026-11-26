#pragma once

#include "../Constants/WifiDefenitions.h"

#include <cstdint>
#include <string>
#include <vector>

// Name of the monitor interface the bridge creates (and deletes on exit).
constexpr const char* MONITOR_INTERFACE = "mmb0";

class InterfaceHandler
{
public:
	~InterfaceHandler();
	static InterfaceHandler& getInstance();

	InterfaceHandler(const InterfaceHandler&) = delete;
	InterfaceHandler& operator=(const InterfaceHandler&) = delete;

	// Error related
	void resolveErrors();

	void setFilters() const;

	// Channel related
	void setFrequency(uint32_t mhz) const;

	// Gives the card back to NetworkManager. Safe to call more than once.
	static void restoreInterface();

	// Getters
	[[nodiscard]] const uint8_t* getInterfaceMac() const;
	[[nodiscard]] std::string getInterfaceName() const;
	[[nodiscard]] int getSocket() const;
	// True when the card ACKs frames to our MAC in hardware (active monitor).
	[[nodiscard]] bool hasHardwareAck() const;

private:
	InterfaceHandler();

	// Initialize
	void createMonitorInterface();
	void initializeInterface();

	// Helpers
	static std::string findManagedInterface();
	static std::string getPhy(const std::string& iface);
	static bool runCommand(const std::vector<std::string>& args);
	void closeSocket();
	void openRawSocket();
	static int getInterfaceIndex(const std::string& iface);
	static bool isMonitorMode(const std::string& iface);
	static void handleSignal(int sig);

	// Device
	int m_socket;
	uint8_t m_interfaceMac[MAC_SIZE_BYTES];
	std::string m_interfaceName;
	bool m_hardwareAck;

	// The managed interface we took from NetworkManager (restored on exit)
	static std::string s_managedInterface;
};
