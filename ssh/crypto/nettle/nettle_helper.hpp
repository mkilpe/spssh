#ifndef SP_SSH_CRYPTO_NETTLE_HELPER_HEADER
#define SP_SSH_CRYPTO_NETTLE_HELPER_HEADER

#include "ssh/common/types.hpp"
#include <nettle/bignum.h>

namespace securepath::ssh::nettle {

struct integer {
	integer() {
		mpz_init(handle);
	}

	integer(unsigned long int value) {
		mpz_init_set_ui(handle, value);
	}

	integer(mpz_t const v) {
		mpz_init_set(handle, v);
	}

	integer(const_span data) {
		nettle_mpz_init_set_str_256_u(handle, data.size(), to_uint8_ptr(data));
	}

	~integer() {
		// zero limbs before freeing to prevent sensitive values lingering in freed memory.
		if(handle->_mp_alloc > 0 && handle->_mp_d) {
			volatile mp_limb_t* p = handle->_mp_d;
			for(mp_size_t i = 0; i < handle->_mp_alloc; ++i) {
				p[i] = 0;
			}
		}
		mpz_clear(handle);
	}

	integer(integer const& i) {
		mpz_init_set(handle, i.handle);
	}

	integer& operator=(integer const& i) {
		mpz_set(handle, i.handle);
		return *this;
	}

	operator mpz_t const&() const {
		return handle;
	}

	operator mpz_t&() {
		return handle;
	}

	mpz_t handle;
};

}

#endif
