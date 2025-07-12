//
// Created by yakov on 6/12/25.
//
#pragma once
#include "ConnectionHandler.h"

class Manager
{
public:
    Manager();
    void connectToNetwork(const BasicNetworkInfo& networkInfo);
private:
    AdapterHandler& m_network;
    ConnectionHandler m_connection;
};

extern Manager manager;