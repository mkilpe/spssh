#ifndef SP_SHH_CLIENT_HEADER
#define SP_SHH_CLIENT_HEADER

#include "ssh/core/ssh_transport.hpp"

namespace securepath::ssh {


/** \brief SSH Version 2 Client side
 */
class ssh_client : public ssh_transport {
public:
	ssh_client(ssh_config const&, logger& log, out_buffer&, crypto_context = default_crypto_context());

private:
};

}

#endif
