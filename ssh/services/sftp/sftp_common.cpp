#include "sftp_common.hpp"
#include "packet_ser.hpp"
#include "packet_ser_impl.hpp"

namespace securepath::ssh::sftp {

std::size_t const sftp_header_size = ser::uint32::static_size + 1; //length + type tag

sftp_common::sftp_common(transport_base& transport, channel_side_info local, std::size_t buffer_size)
: channel(transport, local, buffer_size)
{
	//t: parameterise this
	in_data_.resize(1024*256);
}

sftp_common::sftp_common(channel&& predecessor)
: channel(std::move(predecessor))
{

}

sftp_common::~sftp_common()
{
}

bool sftp_common::on_data(const_span s) {
	if(in_data_.size() - in_used_ < s.size()) {
		// cannot handle, buffer full
		return false;
	}

	copy(s, safe_subspan(in_data_, in_used_, s.size()));
	in_used_ += s.size();

	std::size_t used_size{};
	sftp_packet_type type{};
	do {
		std::uint32_t length{};
		auto span = safe_subspan(in_data_, used_size, in_used_ - used_size);
		type = decode_sftp_type(span, length);
		if(type && length) {
			handle_sftp_packet(type, safe_subspan(in_data_, used_size+sftp_header_size, length-1));
		}
	} while(type != 0);

	if(used_size) {
		std::memmove(in_data_.data(), in_data_.data()+used_size, in_used_ - used_size);
	}

	adjust_in_window(used_size);
	return true;
}

void sftp_common::close(std::string_view error) {
	if(!error.empty()) {
		log_.log(logger::error, "sftp error: {}", error);
	}
	//transport_.set_error_and_disconnect(ssh_protocol_error);
	// try send close on error ?
}

}
