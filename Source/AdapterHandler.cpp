#include "AdapterHandler.h"

//for setups
#include <csignal>
#include <cstring>
#include <filesystem>
#include <memory>
#include <iostream>

///for sockets
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/filter.h>

//for filters
#include "pcap.h"

constexpr uint32_t TIMEOUT = 100;

AdapterHandler AdapterHandler::m_instance = AdapterHandler();

AdapterHandler::AdapterHandler() :  m_deviceMac{0}
{
    system("sudo airmon-ng start wlan0 > /dev/null 2>&1"); //temporary and only for testing later will be using system api
    try
    {
        initDevice();
        initDeviceNetwork();
        setFilters();
    }
    catch (std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
    atexit(AdapterHandler::setDeviceToManaged);
    signal(SIGINT, AdapterHandler::setDeviceToManaged);   // Ctrl+C
    signal(SIGTERM, AdapterHandler::setDeviceToManaged);  // kill
    signal(SIGHUP, AdapterHandler::setDeviceToManaged);
    signal(SIGSEGV, AdapterHandler::setDeviceToManaged);
}

AdapterHandler::~AdapterHandler()
{
    closeSocket();
}

AdapterHandler& AdapterHandler::getInstance()
{
    return m_instance;
}


void AdapterHandler::initDevice()
{
    m_deviceName = findWirelessInterface();
    if (m_deviceName.empty())
        throw std::runtime_error("No wireless interface found");

    openRawSocket();

    int ifindex = getInterfaceIndex(m_deviceName);

    sockaddr_ll sll = {};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;

    if (bind(m_socket, (sockaddr*)&sll, sizeof(sll)) < 0) {
        closeSocket();
        throw std::runtime_error("Failed to bind AF_PACKET socket");
    }

    if (!isMonitorMode(m_deviceName)) {
        closeSocket();
        throw std::runtime_error("Interface is not in monitor mode");
    }
}

void AdapterHandler::initDeviceNetwork()
{
    ifaddrs* addrs = nullptr;
    if (getifaddrs(&addrs) < 0)
        throw std::runtime_error("Failed to get network interfaces");

    bool foundMac = false;
    for (ifaddrs* addr = addrs; addr != nullptr && !foundMac; addr = addr->ifa_next) {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_PACKET) {
            if (addr->ifa_name && m_deviceName == addr->ifa_name) {
                auto* s = reinterpret_cast<sockaddr_ll*>(addr->ifa_addr);
                memcpy(m_deviceMac, s->sll_addr, 6);
                foundMac = true;
            }
        }
    }
    freeifaddrs(addrs);

    if (!foundMac)
        throw std::runtime_error("Cannot find MAC address of device");
}

std::string AdapterHandler::findWirelessInterface()
{
    for (const auto& entry : std::filesystem::directory_iterator("/sys/class/net")) {
        std::string iface = entry.path().filename();
        if (std::filesystem::exists("/sys/class/net/" + iface + "/wireless"))
            return iface;
    }
    throw std::runtime_error("no wireless interfaces");
}

void AdapterHandler::closeSocket()
{
    if (m_socket >= 0) {
        close(m_socket);
        m_socket = -1;
    }
}

void AdapterHandler::openRawSocket()
{
    m_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (m_socket < 0)
        throw std::runtime_error("Failed to create AF_PACKET socket");
}

int AdapterHandler::getInterfaceIndex(const std::string &iface)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        throw std::runtime_error("Failed to open ioctl socket for interface index");

    ifreq ifr = {};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        close(sock);
        throw std::runtime_error("Failed to get interface index");
    }
    close(sock);
    return ifr.ifr_ifindex;
}

bool AdapterHandler::isMonitorMode(const std::string &iface)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        throw std::runtime_error("Failed to open ioctl socket for monitor mode check");

    iwreq iwreq = {};
    strncpy(iwreq.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIWMODE, &iwreq) < 0) {
        close(sock);
        throw std::runtime_error("Failed to get wireless mode");
    }
    close(sock);

    return iwreq.u.mode == IW_MODE_MONITOR;
}

void AdapterHandler::resolveErrors()
{
    initDevice(); //if it will throw again then abort
    initDeviceNetwork();
    setFilters();
}

void AdapterHandler::setFilters()
{
    char buf[18]; // 6*2 hex + 5 colons + 1 null terminator
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             m_deviceMac[0], m_deviceMac[1], m_deviceMac[2],
             m_deviceMac[3], m_deviceMac[4], m_deviceMac[5]);
    std::string macStr = buf;

    std::string filterExp = "wlan addr1 " + macStr + " and (wlan[0] & 0x0C) != 0x04";

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

    struct sock_fprog prog;
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

void AdapterHandler::setDeviceToManaged()
{
    system("sudo airmon-ng stop wlan0mon > /dev/null 2>&1"); //temporary and only for testing later will be using system api
}

void AdapterHandler::setDeviceToManaged(int sig)
{
    system("sudo airmon-ng stop wlan0mon > /dev/null 2>&1"); //temporary and only for testing later will be using system api
}


const uint8_t * AdapterHandler::getDeviceMac() const
{
    return m_deviceMac;
}

std::string AdapterHandler::getDeviceName() const
{
    return m_deviceName;
}

int AdapterHandler::getSocket() const
{
    return m_socket;
}

