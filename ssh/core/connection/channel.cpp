
#include "channel.hpp"
#include "ssh/core/packet_ser_impl.hpp"

namespace securepath::ssh {

channel::channel(transport_base& transport, channel_side_info local, std::size_t buffer_size)
: channel_base(local.id)
, transport_(transport)
, local_info_(std::move(local))
{
	buffer_.resize(buffer_size);
}

template<typename Packet>
bool channel::write_to_buffer(Packet& packet) {
	std::size_t size = packet.size();
	if(buffer_.size() - used_ < size) {
		transport_.log().log(logger::debug, "channel internal buffer full, dropping outgoing packet");
		return false;
	}

	auto s = safe_subspan(buffer_, used_, size);
	bool ret = packet.write(s);
	if(ret) {
		used_ += size;
	} else {
		transport_.log().log(logger::error, "failed to serialise packet to channel internal buffer");
	}

	return ret;
}

template<typename Packet>
bool channel::write_data(Packet& packet, std::size_t data_size) {

	// first see if we are out of window or there is something in buffer and add to buffer is that is the case
	if(used_ || out_window_ < data_size) {
		return write_to_buffer(packet);
	}

	// try to allocated space from the main out buffer to send directly
	auto rec = transport_.alloc_out_packet(packet.size());

	// if we can't, add to buffer
	if(!rec) {
		return write_to_buffer(packet);
	}

	if(packet.write(rec->data)) {
		return transport_.write_alloced_out_packet(*rec);
	} else {
		transport_.set_error(spssh_invalid_packet, "Failed to serialise outgoing packet");
	}

	return false;
}

template bool channel::write_data(ser::channel_data::save& packet, std::size_t data_size);
template bool channel::write_data(ser::channel_extended_data::save& packet, std::size_t data_size);

bool channel::send_data(const_span s) {
	ser::channel_data::save packet(remote_info_.id, to_string_view(s));
	return write_data(packet, s.size());
}

bool channel::send_extended_data(std::uint32_t data_type, const_span s) {
	ser::channel_extended_data::save packet(remote_info_.id, data_type, to_string_view(s));
	return write_data(packet, s.size());
}

bool channel::send_eof() {
	ser::channel_eof::save packet(remote_info_.id);
	return write_data(packet, 0);
}

bool channel::send_close() {
	ser::channel_close::save packet(remote_info_.id);
	return write_data(packet, 0);
}

bool channel::send_window_adjust(std::uint32_t n) {
	ser::channel_window_adjust::save packet(remote_info_.id, n);
	bool ret = write_data(packet, 0);
	if(ret) {
		in_window_ -= std::min(n, in_window_);
	}
	return ret;
}

bool channel::send_open(std::string_view type) {
	return transport_.send_packet<ser::channel_open>(
		type,
		local_info_.id,
		local_info_.window_size,
		local_info_.max_packet_size);
}

bool channel::on_open(channel_side_info remote, const_span /*extra_data*/) {
	remote_info_ = remote;
	return transport_.send_packet<ser::channel_open_confirmation>(
			remote_info_.id,
			local_info_.id,
			local_info_.window_size,
			local_info_.max_packet_size);
}

bool channel::on_confirm(const_span /*extra_data*/) {
	return true;
}

void channel::on_failure(std::uint32_t code, std::string_view message) {
	transport_.log().log(logger::info, "failed to open channel (remote refuses) [code={}, msg={}]", code, message);
}

void channel::on_data(const_span) {

}

void channel::on_extended_data(std::uint32_t data_type, const_span) {

}

void channel::on_window_adjust(std::uint32_t bytes) {

}

void channel::on_eof() {

}

void channel::on_close() {

}

}

