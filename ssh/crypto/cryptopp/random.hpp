#ifndef SP_SSH_CRYPTO_CRYPTOPP_RANDOM_HEADER
#define SP_SSH_CRYPTO_CRYPTOPP_RANDOM_HEADER

#include <cryptopp/osrng.h>

namespace securepath::ssh::cryptopp {

using random_gen = CryptoPP::AutoSeededX917RNG<CryptoPP::AES>;

random_gen& random_generator();

}

#endif
