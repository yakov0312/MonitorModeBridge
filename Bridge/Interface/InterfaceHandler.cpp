#include "InterfaceHandler.h"

// For filters
#include "pcap.h"

// For setups
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

// For sockets
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

extern char** environ;

constexpr uint16_t ARPHRD_RADIOTAP_TYPE = 803; // ARPHRD_IEEE80211_RADIOTAP

std::string InterfaceHandler::s_managedInterface;
static std::atomic<bool> s_restored{false};

InterfaceHandler::InterfaceHandler() : m_socket(-1), m_interfaceMac{}, m_hardwareAck(false)
{
    // Register cleanup first so a failure half way still gives the card back
    atexit(restoreInterface);
    signal(SIGINT, handleSignal);   // Ctrl+C
    signal(SIGTERM, handleSignal);  // kill
    signal(SIGHUP, handleSignal);
    signal(SIGSEGV, handleSignal);

    try
    {
        createMonitorInterface();
        initializeInterface();
        setFilters();
    }
    catch (std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
}

InterfaceHandler::~InterfaceHandler()
{
    closeSocket();
    restoreInterface();
}

InterfaceHandler& InterfaceHandler::getInstance()
{
    static InterfaceHandler instance;
    return instance;
}

/*
 * Run a command without a shell. Returns true on exit status 0.
 * Output is discarded; the bridge prints its own errors.
 */
bool InterfaceHandler::runCommand(const std::vector<std::string>& args)
{
    std::vector<char*> argv;
    for (const auto& arg : args)
        argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    pid_t pid;
    const int err = posix_spawnp(&pid, argv[0], &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    if (err != 0)
        return false;

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return false;

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

std::string InterfaceHandler::getPhy(const std::string& iface)
{
    const std::filesystem::path link = "/sys/class/net/" + iface + "/phy80211";
    if (!std::filesystem::exists(link))
        throw std::runtime_error("Cannot find the wireless phy of " + iface);

    return std::filesystem::read_symlink(link).filename();
}

/*
 * Create our own monitor interface on the card's phy:
 *   iw phy <phy> interface add mmb0 type monitor flags active control otherbss
 * "active" makes the card ACK frames sent to the interface's MAC in hardware.
 * Cards/drivers without active monitor support get a plain monitor interface
 * and the bridge falls back to sending ACKs itself.
 */
void InterfaceHandler::createMonitorInterface()
{
    // Remove a leftover interface from a previous run
    if (std::filesystem::exists(std::string("/sys/class/net/") + MONITOR_INTERFACE))
        runCommand({"iw", "dev", MONITOR_INTERFACE, "del"});

    s_managedInterface = findManagedInterface();
    const std::string phy = getPhy(s_managedInterface);

    // Take the card away from NetworkManager so it does not fight us
    runCommand({"nmcli", "device", "set", s_managedInterface, "managed", "no"});
    runCommand({"ip", "link", "set", s_managedInterface, "down"});
    s_restored = false;

    m_hardwareAck = runCommand({"iw", "phy", phy, "interface", "add", MONITOR_INTERFACE,
        "type", "monitor", "flags", "active", "control", "otherbss"});

    if (!m_hardwareAck &&
        !runCommand({"iw", "phy", phy, "interface", "add", MONITOR_INTERFACE,
            "type", "monitor", "flags", "control", "otherbss"}))
        throw std::runtime_error("Failed to create monitor interface on " + phy);

    // For comparing against the old behaviour: MMB_SOFTWARE_ACK=1
    if (const char* env = std::getenv("MMB_SOFTWARE_ACK"); env && env[0] == '1')
        m_hardwareAck = false;

    if (!runCommand({"ip", "link", "set", MONITOR_INTERFACE, "up"}))
        throw std::runtime_error(std::string("Failed to bring up ") + MONITOR_INTERFACE);

    std::cout << "Monitor interface " << MONITOR_INTERFACE << " on " << phy
              << (m_hardwareAck ? " (active monitor: hardware ACK)"
                                : " (plain monitor: software ACK)") << std::endl;
}

void InterfaceHandler::initializeInterface()
{
    m_interfaceName = MONITOR_INTERFACE;

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


std::string InterfaceHandler::findManagedInterface()
{
    for (const auto& entry : std::filesystem::directory_iterator("/sys/class/net"))
    {
        std::string iface = entry.path().filename();
        if (iface == MONITOR_INTERFACE)
            continue;

        if (std::filesystem::exists("/sys/class/net/" + iface + "/phy80211") && !isMonitorMode(iface))
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

/*
 * Monitor interfaces deliver radiotap frames (link type 803). Wireless
 * extensions (SIOCGIWMODE) are not available on kernels built without
 * CONFIG_CFG80211_WEXT, e.g. Fedora.
 */
bool InterfaceHandler::isMonitorMode(const std::string &iface)
{
    std::ifstream typeFile("/sys/class/net/" + iface + "/type");
    int type = 0;
    if (!(typeFile >> type))
        throw std::runtime_error("Failed to get link type of " + iface);

    return type == ARPHRD_RADIOTAP_TYPE;
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

void InterfaceHandler::setFrequency(const uint32_t mhz) const
{
    if (!runCommand({"iw", "dev", m_interfaceName, "set", "freq", std::to_string(mhz)}))
        throw std::runtime_error("Can't set frequency " + std::to_string(mhz) + " MHz");
}

void InterfaceHandler::restoreInterface()
{
    if (s_managedInterface.empty() || s_restored.exchange(true))
        return;

    runCommand({"iw", "dev", MONITOR_INTERFACE, "del"});
    runCommand({"ip", "link", "set", s_managedInterface, "up"});
    runCommand({"nmcli", "device", "set", s_managedInterface, "managed", "yes"});
}

void InterfaceHandler::handleSignal(const int sig)
{
    restoreInterface();
    // Default action (terminate / core dump) instead of returning into the
    // code that crashed or was interrupted.
    signal(sig, SIG_DFL);
    raise(sig);
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

bool InterfaceHandler::hasHardwareAck() const
{
    return m_hardwareAck;
}

