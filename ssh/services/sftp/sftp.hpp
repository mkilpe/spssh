#ifndef SP_SSH_SFTP_HEADER
#define SP_SSH_SFTP_HEADER

#include "ssh/common/types.hpp"

namespace securepath::ssh::sftp {

// https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
std::uint32_t const sftp_version{3};

struct ext_data {
	std::string_view type;
	std::string_view data;
};

}

#endif