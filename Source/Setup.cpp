//
// Created by yakov on 6/12/25.
//
#include "Setup.h"

Setup::Setup() : m_network(NetworkHandler::getInstance())
{
	m_network.checkErr();
}


int ConnectToNetwork(const NetworkInfo::BasicNetworkInfo &networkInfo)
{
	return 0;
}
