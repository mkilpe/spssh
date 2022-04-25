#include "util.hpp"

#include <fstream>

namespace securepath::ssh {

byte_vector read_file(std::string const& file) {
	byte_vector b;
	std::ifstream f(file, std::ios_base::binary);
	if(f) {
		f.seekg(0, std::ios_base::end);
		auto size = f.tellg();
		f.seekg(0, std::ios_base::beg);
		b.resize(size);
		f.read((char*)b.data(), size);
	}
	return b;
}

}