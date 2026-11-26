//
// Created by yakov on 6/17/25.
//
#include <iostream>
#include <Core/Manager.h>
#include "exception"

int main(int argc, char* argv[])
{
	if (argc < 2 || argc > 3)
	{
		std::cerr << "usage: " << argv[0] << " <ssid> [password]" << std::endl;
		return 1;
	}

	try
	{
		Manager& m = Manager::getManager();
		m.connectToNetwork(BasicNetworkInfo(argv[1], argc == 3 ? argv[2] : ""));
	}
	catch(const std::exception& e)
	{
		std::cout << e.what() << std::endl;
		return 1;
	}
}
