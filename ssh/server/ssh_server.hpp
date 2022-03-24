#ifndef SP_SHH_SERVER_HEADER
#define SP_SHH_SERVER_HEADER

#include "ssh/core/ssh_transport.hpp"

namespace securepath::ssh {


/** \brief SSH Version 2 Server side
 */
class ssh_server : public ssh_transport {
public:
	ssh_server(ssh_config const&, logger& log, out_buffer&, crypto_context = default_crypto_context());

private:
};

}

#endif
