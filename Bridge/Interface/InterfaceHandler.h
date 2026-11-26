#pragma once

#include "../Constants/WifiDefenitions.h"

#include <string>

// nl80211 context
#include <netlink/netlink.h>

class InterfaceHandler
{
public:
    ~InterfaceHandler();
    static InterfaceHandler& getInstance();

    // Device management
    [[nodiscard]] bool setInterfaceChannel(uint16_t channel) const;

    // Error recovery
    void resolveErrors();

    // Packet filter
    void setFilters() const;

    // Restore device
    static void setInterfaceToManaged();
    static void setInterfaceToManaged(int sig);

    // Getters
    [[nodiscard]] const uint8_t* getInterfaceMac() const;
    [[nodiscard]] std::string getInterfaceName() const;
    [[nodiscard]] int getSocket() const;
    [[nodiscard]] static uint16_t getInterfaceChannel();

private:
    InterfaceHandler();

    // Device setup flow
    void initNL();
    void setMonitorMode() const;
    void initializeInterface();

    // Helpers
    void findWirelessInterface();
    void openRawSocket();
    void closeSocket();

    [[nodiscard]] bool setInterfaceMode(uint32_t mode) const;
    [[nodiscard]] bool setInterfaceState(bool up);

    struct nl80211_ctx
    {
        nl_sock* genericSock = nullptr;
        nl_sock* rtSock = nullptr;
        int family = -1;
    };

    nl80211_ctx m_nl;

    int m_socket;
    uint8_t m_interfaceMac[MAC_SIZE_BYTES];
    std::string m_interfaceName;
    uint32_t m_interfaceIndex;
    bool m_interfaceState = true; // UP

    static uint16_t m_channel;

    static InterfaceHandler m_instance;
};