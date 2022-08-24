#include "sftp_client.hpp"

namespace securepath::ssh::sftp {

sftp_client::sftp_client(transport_base& transport, channel_side_info local, std::size_t buffer_size)
: channel(transport, local, buffer_size)
{
}

}
