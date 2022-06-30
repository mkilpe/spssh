
#include "channel.hpp"
#include "conn_protocol.hpp"

namespace securepath::ssh {

channel::channel(transport_base& transport)
: transport_(transport)
{
}

template<typename Packet>
bool channel::write_to_buffer(Packet const& packet) {

}

template<typename Packet>
bool channel::write_data(Packet const& packet) {

	// first see if we are out of window and add to buffer is that is the case
	if(out_window_ < s.size()) {
		return write_to_buffer(packet);
	}

	// try to allocated space from the main out buffer to send directly
	auto rec = transport_.alloc_out_packet(packet.size());

	// if we can't, add to buffer
	if(!rec) {
		return write_to_buffer(packet);
	}

	if(packet.write(rec->data)) {
		return write_alloced_out_packet(*rec);
	} else {
		set_error(spssh_invalid_packet, "Failed to serialise outgoing packet");
	}
}

bool channel::send_data(const_span s) {
	channel_data::save packet(recipient_channel_, to_string_view(s));
}

bool channel::send_extended_data(const_span s) {

}

bool channel::send_eof() {

}

bool channel::send_close() {

}

bool channel::send_window_adjust(std::uint32_t n) {

}

}

