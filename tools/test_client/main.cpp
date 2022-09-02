
#include "client.hpp"

#include <stdexcept>
#include <iostream>

int main(int argc, char* argv[]) {
	try {
		using namespace securepath::ssh;
		test_client_commands p;
		p.parse(argc, argv);
		if(p.help) {
			std::cout << "spssh test client\n";
			test_client_commands().print_help(std::cout);
			return 0;
		}
		if(!p.config_file.empty()) {
			p.parse_file(p.config_file);
		}

		test_client client(p);
		client.run();
	} catch(std::exception const& e) {
		std::cerr << "Exception: " << e.what() << "\n";
		return 1;
	}
}
