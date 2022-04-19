#ifndef SP_SHH_AUTH_HEADER
#define SP_SHH_AUTH_HEADER

namespace securepath::ssh {

// supported authentication types [RFC 4252] [RFC 4256]
enum class auth_type {
	none,
	public_key,
	password,
	hostbased,
	interactive
};

}

#endif