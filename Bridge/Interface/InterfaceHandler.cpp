#include "InterfaceHandler.h"

// For filters
#include "pcap.h"

// For setups
#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>

// For sockets
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

constexpr uint32_t TIMEOUT = 100;

InterfaceHandler InterfaceHandler::m_instance = InterfaceHandler();

InterfaceHandler::InterfaceHandler() :  m_interfaceMac{}
{
    system("sudo airmon-ng start wlan0 > /dev/null 2>&1"); // Temporary and only for testing later will be using system api
    try
    {
        initializeInterface();
        setFilters();
    }
    catch (std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
    atexit(setInterfaceToManaged);
    signal(SIGINT, setInterfaceToManaged);   // Ctrl+C
    signal(SIGTERM, setInterfaceToManaged);  // kill
    signal(SIGHUP, setInterfaceToManaged);
    signal(SIGSEGV, setInterfaceToManaged);
}

InterfaceHandler::~InterfaceHandler()
{
    closeSocket();
}

InterfaceHandler& InterfaceHandler::getInstance()
{
    return m_instance;
}

void InterfaceHandler::initializeInterface()
{
    m_interfaceName = findWirelessInterface();
    if (m_interfaceName.empty())
        throw std::runtime_error("No wireless interface found");

    openRawSocket();

    const int ifindex = getInterfaceIndex(m_interfaceName);

    sockaddr_ll sll = {};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;

    if (bind(m_socket, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0)
    {
        closeSocket();
        throw std::runtime_error("Failed to bind AF_PACKET socket");
    }

    if (!isMonitorMode(m_interfaceName))
    {
        closeSocket();
        throw std::runtime_error("Interface is not in monitor mode");
    }

    ifaddrs* addrs = nullptr;
    if (getifaddrs(&addrs) < 0)
        throw std::runtime_error("Failed to get network interfaces");

    bool foundMac = false;
    for (const ifaddrs* addr = addrs; addr != nullptr && !foundMac; addr = addr->ifa_next)
    {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_PACKET)
        {
            if (addr->ifa_name && m_interfaceName == addr->ifa_name)
            {
                const auto* s = reinterpret_cast<sockaddr_ll*>(addr->ifa_addr);
                memcpy(m_interfaceMac, s->sll_addr, 6);
                foundMac = true;
            }
        }
    }

    freeifaddrs(addrs);

    if (!foundMac)
        throw std::runtime_error("Cannot find MAC address of device");
}


std::string InterfaceHandler::findWirelessInterface()
{
    for (const auto& entry : std::filesystem::directory_iterator("/sys/class/net"))
    {
        std::string iface = entry.path().filename();
        if (std::filesystem::exists("/sys/class/net/" + iface + "/wireless"))
            return iface;
    }

    throw std::runtime_error("no wireless interfaces");
}

void InterfaceHandler::closeSocket()
{
    if (m_socket >= 0)
    {
        close(m_socket);
        m_socket = -1;
    }
}

void InterfaceHandler::openRawSocket()
{
    m_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (m_socket < 0)
        throw std::runtime_error("Failed to create AF_PACKET socket");
}

int InterfaceHandler::getInterfaceIndex(const std::string &iface)
{
    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        throw std::runtime_error("Failed to open ioctl socket for interface index");

    ifreq ifr = {};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
    {
        close(sock);
        throw std::runtime_error("Failed to get interface index");
    }

    close(sock);
    return ifr.ifr_ifindex;
}

bool InterfaceHandler::isMonitorMode(const std::string &iface)
{
    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        throw std::runtime_error("Failed to open ioctl socket for monitor mode check");

    iwreq iwreq = {};
    strncpy(iwreq.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIWMODE, &iwreq) < 0)
    {
        close(sock);
        throw std::runtime_error("Failed to get wireless mode");
    }

    close(sock);

    return iwreq.u.mode == IW_MODE_MONITOR;
}

void InterfaceHandler::resolveErrors()
{
    initializeInterface(); // If it throws again then abort
    setFilters();
}

void InterfaceHandler::setFilters() const
{
    char buf[18]; // 6*2 hex + 5 colons + 1 null terminator
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             m_interfaceMac[0], m_interfaceMac[1], m_interfaceMac[2],
             m_interfaceMac[3], m_interfaceMac[4], m_interfaceMac[5]);
    const std::string macStr = buf;

    const std::string filterExp = "wlan addr1 " + macStr + " and (wlan[0] & 0x0C) != 0x04";

    // Initialize a dummy pcap handle for compilation
    pcap_t* pcap_handle = pcap_open_dead(DLT_IEEE802_11_RADIO, 65535);
    if (!pcap_handle)
        throw std::runtime_error("Failed to open pcap dead handle");

    bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, filterExp.c_str(), 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
    {
        pcap_close(pcap_handle);
        throw std::runtime_error("Failed to compile BPF filter");
    }

    sock_fprog prog;
    prog.len = fp.bf_len;
    prog.filter = reinterpret_cast<sock_filter*>(fp.bf_insns);

    // Attach the filter to the AF_PACKET socket
    if (setsockopt(m_socket, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
    {
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
        throw std::runtime_error("Failed to attach BPF filter to socket");
    }

    pcap_freecode(&fp);
    pcap_close(pcap_handle);
}

void InterfaceHandler::setInterfaceToManaged()
{
    system("sudo airmon-ng stop wlan0mon > /dev/null 2>&1"); // Temporary and only for testing later will be using system api
}

void InterfaceHandler::setInterfaceToManaged(int sig)
{
    system("sudo airmon-ng stop wlan0mon > /dev/null 2>&1"); // Temporary and only for testing later will be using system api
}


const uint8_t* InterfaceHandler::getInterfaceMac() const
{
    return m_interfaceMac;
}

std::string InterfaceHandler::getInterfaceName() const
{
    return m_interfaceName;
}

int InterfaceHandler::getSocket() const
{
    return m_socket;
}

