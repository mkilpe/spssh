#include "../random.hpp"

#include <securepath/crypto/random.hpp>

namespace securepath::ssh {

void random_bytes(span output) {
	crypto::random_data(output.size(), reinterpret_cast<std::uint8_t*>(output.data()));
}

std::size_t random_uint(std::size_t min, std::size_t max) {
	return crypto::random_number(min, max);
}

}