//
// Created by yakov on 6/12/25.
//
#pragma once
#include <string>

#include "NetworkHandler.h"

constexpr uint8_t MAC_SIZE_BYTES = 6;


namespace NetworkInfo
{
    struct BasicNetworkInfo
    {
        std::string networkName;
        std::string networkPassword; //optional - based on security
    };

    struct FullNetworkInfo
    {
        uint32_t ipAddress;
        uint32_t netmask;
        uint8_t macAddress[MAC_SIZE_BYTES];
        uint8_t channel;
    };
}

class HIDDEN Setup
{
public:
    Setup();

private:
    NetworkHandler& m_network;
};


CTOR static void onLibraryLoad();

int ConnectToNetwork(const NetworkInfo::BasicNetworkInfo& networkInfo);

