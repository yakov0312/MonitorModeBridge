//
// Created by yakov on 6/17/25.
//
#include <iostream>
#include <string>
#include <vector>
#include <Core/Manager.h>
#include "exception"

static void usage(const char* prog)
{
	std::cerr << "usage: " << prog << " [--iface <name>] <ssid> [password]\n"
		"  --iface <name>  use this interface instead of a temporary mmb0.\n"
		"                  A managed interface is switched to monitor mode in place,\n"
		"                  one already in monitor mode is used as-is. It is left in\n"
		"                  monitor mode on exit so you can capture it (Wireshark).\n";
}

int main(int argc, char* argv[])
{
	std::vector<std::string> positional;
	for (int i = 1; i < argc; i++)
	{
		const std::string arg = argv[i];
		if (arg == "--iface" && i + 1 < argc)
			InterfaceHandler::useInterface(argv[++i]);
		else if (arg == "-h" || arg == "--help" || arg.rfind("--", 0) == 0)
		{
			usage(argv[0]);
			return arg == "-h" || arg == "--help" ? 0 : 1;
		}
		else
			positional.push_back(arg);
	}

	if (positional.empty() || positional.size() > 2)
	{
		usage(argv[0]);
		return 1;
	}

	try
	{
		Manager& m = Manager::getManager();
		m.connectToNetwork(BasicNetworkInfo(positional[0], positional.size() == 2 ? positional[1] : ""));
	}
	catch(const std::exception& e)
	{
		std::cout << e.what() << std::endl;
		return 1;
	}
}
