#ifndef SP_SHH_CORE_UTIL_HEADER
#define SP_SHH_CORE_UTIL_HEADER

#include "ssh/common/types.hpp"
#include "ssh/crypto/hash.hpp"

namespace securepath::ssh {

class binout {
public:
	virtual bool process(const_span data) = 0;
protected:
	~binout() = default;
};

struct hash_binout : binout {
	hash_binout(ssh::hash& hash);

	bool process(const_span data) override;

public:
	ssh::hash& hash;
};

struct byte_vector_binout : binout {
	byte_vector_binout(byte_vector& buf);

	bool process(const_span data) override;

public:
	byte_vector& buf;
};

struct string_binout : binout {
	string_binout(std::string& buf);

	bool process(const_span data) override;

public:
	std::string& buf;
};

}

#endif
