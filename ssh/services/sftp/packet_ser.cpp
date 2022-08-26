#include "packet_ser.hpp"

#include "ssh/core/ssh_binary_util.hpp"

namespace securepath::ssh::sftp {

sftp_packet_type decode_sftp_type(const_span s, std::uint32_t& length) {
	sftp_packet_type res{};
	ssh_bf_reader reader(s);
	if(reader.read(length) && reader.size_left() >= length) {
		reader.read((std::uint8_t&)res);
	}
	return res;
}

}
