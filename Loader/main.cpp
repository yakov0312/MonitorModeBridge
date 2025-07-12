//
// Created by yakov on 6/17/25.
//
#include <iostream>
#include "Manager.h"
#include "exception"

int main()
{
	try
	{
		manager.connectToNetwork(BasicNetworkInfo("Dudnik", "0546424000"));
	}
	catch(const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
}
