// Created by yakov on 6/12/25.

#include "Manager.h"
#include "../Constants/WifiDefenitions.h"

Manager & Manager::getManager()
{
	static Manager instance;
	return instance;
}

Manager::Manager() : m_network(InterfaceHandler::getInstance())
{
}

void Manager::connectToNetwork(const BasicNetworkInfo& networkInfo)
{
	this->m_connection.connect(networkInfo);
}
