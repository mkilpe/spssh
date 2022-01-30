#ifndef SP_SHH_SERVER_HEADER
#define SP_SHH_SERVER_HEADER

#include "ssh/common/ssh_transport.hpp"

namespace securepath::ssh {


/** \brief SSH Version 2 Server side
 */
class ssh_server : private ssh_transport {
public:
	ssh_server(ssh_config const&, fz::logger_interface* logger = nullptr);


};

}

#endif
