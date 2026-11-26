#pragma once

#include "../Constants/WifiDefenitions.h"

#include <cstdint>
#include <string>
#include <vector>

// nl80211 context
#include <netlink/netlink.h>

// Name of the monitor interface the bridge creates (and deletes on exit).
constexpr const char* MONITOR_INTERFACE = "mmb0";

class InterfaceHandler
{
public:
    ~InterfaceHandler();
    static InterfaceHandler& getInstance();

    InterfaceHandler(const InterfaceHandler&) = delete;
    InterfaceHandler& operator=(const InterfaceHandler&) = delete;

    // Device management
    [[nodiscard]] bool setInterfaceChannel(uint16_t channel) const;

    // Error recovery
    void resolveErrors();

    // Packet filter
    void setFilters() const;

    // Restore device: delete the monitor interface and give the card back
    // to NetworkManager. Safe to call more than once.
    static void setInterfaceToManaged();

    // Getters
    [[nodiscard]] const uint8_t* getInterfaceMac() const;
    [[nodiscard]] std::string getInterfaceName() const;
    [[nodiscard]] int getSocket() const;
    [[nodiscard]] static uint16_t getInterfaceChannel();
    // True when the card ACKs frames to our MAC in hardware (active monitor).
    [[nodiscard]] bool hasHardwareAck() const;

private:
    InterfaceHandler();

    // Device setup flow
    void initNL();
    void findWirelessInterface();
    void createMonitorInterface();
    void initializeInterface();
    void restore();

    // Helpers
    void openRawSocket();
    void closeSocket();

    [[nodiscard]] bool newMonitorInterface(bool active) const;
    [[nodiscard]] bool deleteInterface(uint32_t ifindex) const;
    [[nodiscard]] bool setInterfaceState(uint32_t ifindex, bool up) const;
    [[nodiscard]] bool sendAndWait(nl_msg* msg) const;

    static bool isMonitorMode(const std::string& iface);
    static bool runCommand(const std::vector<std::string>& args);
    static void handleSignal(int sig);

    struct nl80211_ctx
    {
        nl_sock* genericSock = nullptr;
        nl_sock* rtSock = nullptr;
        int family = -1;
    };

    nl80211_ctx m_nl;

    int m_socket;
    uint8_t m_interfaceMac[MAC_SIZE_BYTES];

    // The monitor interface we created (mmb0)
    std::string m_interfaceName;
    uint32_t m_interfaceIndex;
    bool m_hardwareAck;

    // The managed interface we took from NetworkManager (restored on exit)
    std::string m_managedName;
    uint32_t m_managedIndex;
    uint32_t m_wiphy;

    static uint16_t m_channel;
};
