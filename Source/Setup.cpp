//
// Created by yakov on 6/12/25.
//
#include "Setup.h"

#include "WifiRelatedPackets.h"

Setup::Setup() : m_network(AdapterHandler::getInstance())
{
	m_network.checkErr(); //check if there were errors
}


int ConnectToNetwork(const NetworkInfo::BasicNetworkInfo& networkInfo)
{
	return 0;
}
