//
// Created by yakov on 6/17/25.
//
#include <iostream>
#include "Manager.h"
#include "exception"

int main()
{
	system("sudo airmon-ng start wlan0");
	try
	{
		manager.connectToNetwork(BasicNetworkInfo("Dudnik", "054642400"));
	}
	catch(const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
	system("sudo airmon-ng stop wlan0mon");
}
