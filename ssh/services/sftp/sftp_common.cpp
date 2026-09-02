#include "sftp_common.hpp"
#include "packet_ser.hpp"
#include "packet_ser_impl.hpp"
#include <cstring>

namespace securepath::ssh::sftp {

std::size_t const sftp_header_size = ser::uint32::static_size + 1; //length + type tag

bool read_extension_data(ssh_bf_reader& r, std::vector<ext_data_view>& out) {
	bool res = true;
	while(res && !r.rest_of_span().empty()) {
		ext_data_view e{};
		res = r.read(e.type) && r.read(e.data);
		if(res) {
			out.push_back(e);
		}
	}
	return res;
}

sftp_common::sftp_common(transport_base& transport, channel_side_info local, std::size_t buffer_size, std::size_t in_buffer_size)
: channel(transport, local, buffer_size)
{
	SPSSH_ASSERT(in_buffer_size >= sftp_header_size, "too small sftp in buffer");
	in_data_.resize(in_buffer_size);
}

sftp_common::sftp_common(channel&& predecessor, std::size_t in_buffer_size)
: channel(std::move(predecessor))
{
	SPSSH_ASSERT(in_buffer_size >= sftp_header_size, "too small sftp in buffer");
	in_data_.resize(in_buffer_size);
}

sftp_common::~sftp_common()
{
}

bool sftp_common::is_valid_packet_length(std::uint32_t length) const {
	// the length must be at least 1 (the type tag) and the whole packet must fit into our buffer
	return length != 0 && length <= in_data_.size() - (sftp_header_size - 1);
}

bool sftp_common::on_data(const_span s) {
	log_.log(logger::debug_trace, "sftp on data [used={}]", in_used_);

	if(in_data_.size() - in_used_ < s.size()) {
		log_.log(logger::debug_trace, "buffer full");
		// cannot handle, buffer full
		return false;
	}

	copy(s, safe_subspan(in_data_, in_used_));
	in_used_ += s.size();

	std::size_t used_size{};
	bool more = true;
	while(more) {
		more = false;
		std::uint32_t length{};
		auto span = safe_subspan(in_data_, used_size, in_used_ - used_size);
		auto type = decode_sftp_type(span, length);
		log_.log(logger::debug_trace, "sftp decode packet [type={}, length={}, data size={}]", int(type), length, in_used_ - used_size);
		if(span.size() >= ser::uint32::static_size && !is_valid_packet_length(length)) {
			log_.log(logger::error, "sftp packet length out of bounds [length={}]", length);
			transport_.set_error_and_disconnect(ssh_protocol_error);
			return true;
		}
		if(type && length) {
			handle_sftp_packet(type, safe_subspan(in_data_, used_size+sftp_header_size, length-1));
			used_size += sftp_header_size + length - 1;
			more = true;
		}
	}

	if(used_size) {
		std::memmove(in_data_.data(), in_data_.data()+used_size, in_used_ - used_size);
		in_used_ -= used_size;
		log_.log(logger::debug_trace, "sftp packet(s) handled [size={}, used={}]", used_size, in_used_);
		adjust_in_window(used_size);
	}

	return true;
}

void sftp_common::close(std::string_view error) {
	if(!error.empty()) {
		log_.log(logger::error, "sftp error: {}", error);
	}
	send_close();
}

}
