//
// Created by yakov on 6/17/25.
//
#include <iostream>
#include <Core/Manager.h>
#include "exception"

int main()
{
	try
	{
		Manager& m = Manager::getManager();
		m.connectToNetwork(BasicNetworkInfo("Dudnik", "0546424000"));
	}
	catch(const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
}
