#include "sftp_server.hpp"

namespace securepath::ssh::sftp {

sftp_server::sftp_server(transport_base& transport, channel_side_info local, std::size_t buffer_size)
: channel(transport, local, buffer_size)
{
}

}
