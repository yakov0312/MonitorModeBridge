// Created by yakov on 6/12/25.

#pragma once

#include <ApConnection/ConnectionHandler.h>

class Manager
{
public:
    static Manager& getManager();

    void connectToNetwork(const BasicNetworkInfo& networkInfo);

private:
    Manager();
    Manager(Manager const&) = delete;
    Manager& operator=(Manager const&) = delete;

    InterfaceHandler& m_network;
    ConnectionHandler m_connection;
};
