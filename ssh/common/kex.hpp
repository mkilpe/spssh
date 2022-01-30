#ifndef SP_SHH_KEX_HEADER
#define SP_SHH_KEX_HEADER


namespace securepath::ssh::server {

class kex : public ssh_layer {
public:
	virtual ~kex() = default;

	// interface to get kex result data
};

}

#endif
