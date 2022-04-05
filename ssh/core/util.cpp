
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

}
