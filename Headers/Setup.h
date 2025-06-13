//
// Created by yakov on 6/12/25.
//
#pragma once
#include <string>
#include "ConnectionHandler.h"

class HIDDEN Setup
{
public:
    Setup();

private:
    AdapterHandler& m_network;
};


CTOR static void onLibraryLoad();

int ConnectToNetwork(const BasicNetworkInfo& networkInfo);

