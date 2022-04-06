
#include "util.hpp"

namespace securepath::ssh {

hash_binout::hash_binout(ssh::hash& hash)
: hash(hash)
{
}

bool hash_binout::process(const_span data) {
	hash.process(data);
	return true;
}


byte_vector_binout::byte_vector_binout(byte_vector& buf)
: buf(buf)
{
}

bool byte_vector_binout::process(const_span data) {
	buf.insert(buf.end(), data.begin(), data.end());
	return true;
}

}
