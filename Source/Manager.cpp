//
// Created by yakov on 6/12/25.
//
extern "C" {
#include "libwifi.h"
}

#include "Manager.h"
#include "WifiDefenitions.h"

Manager manager;

Manager::Manager() : m_network(AdapterHandler::getInstance())
{
	m_network.checkErr(); //check if there were errors
}

void Manager::connectToNetwork(const BasicNetworkInfo& networkInfo)
{
	this->m_connection.connect(networkInfo);
}
