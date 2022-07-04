
#include "channel.hpp"
#include "conn_protocol.hpp"

#include "ssh/core/packet_ser_impl.hpp"

namespace securepath::ssh {

channel::channel(transport_base& transport)
: transport_(transport)
{
}

template<typename Packet>
bool channel::write_to_buffer(Packet& packet) {
	return false;
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

bool channel::send_data(const_span s) {
	ser::channel_data::save packet(recipient_channel_, to_string_view(s));
	return write_data(packet, s.size());
}

bool channel::send_extended_data(std::uint32_t data_type, const_span s) {
	ser::channel_extended_data::save packet(recipient_channel_, data_type, to_string_view(s));
	return write_data(packet, s.size());
}

bool channel::send_eof() {
	ser::channel_eof::save packet(recipient_channel_);
	return write_data(packet, 0);
}

bool channel::send_close() {
	ser::channel_close::save packet(recipient_channel_);
	return write_data(packet, 0);
}

bool channel::send_window_adjust(std::uint32_t n) {
	ser::channel_window_adjust::save packet(recipient_channel_, n);
	bool ret = write_data(packet, 0);
	if(ret) {
		in_window_ -= std::min(n, in_window_);
	}
	return ret;
}

}

