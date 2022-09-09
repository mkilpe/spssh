
#include "channel.hpp"
#include "ssh/core/packet_ser_impl.hpp"

#include <algorithm>
#include <limits>

namespace securepath::ssh {

std::string_view to_string(channel_state s) {
	using enum channel_state;
	switch(s) {
		case init:          return "init";
		case open_pending:  return "open_pending";
		case established:   return "established";
		case close_pending: return "close_pending";
		case closed:        return "closed";
	}
	return "unknown";
}

std::uint32_t const packet_overhead = 32;

channel::channel(transport_base& transport, channel_side_info local, std::size_t buffer_size)
: channel_base(local.id)
, transport_(transport)
, log_(transport_.log())
, local_info_(std::move(local))
{
	log_.log(logger::debug_trace, "channel id={} constructed", local.id);
	buffer_.resize(buffer_size);

	local_info_.max_packet_size =
		std::min(local_info_.max_packet_size, transport_.max_in_packet_size())-packet_overhead;
}

channel::~channel()
{
	log_.log(logger::debug_trace, "channel id={} destroyed", local_info_.id);
}

std::uint32_t channel::write_to_buffer(const_span data, bool partial) {
	std::size_t size = std::min(data.size(), buffer_.size() - used_);

	// if partial not set, only allow to write all to the buffer
	if(!partial && size != data.size()) {
		return 0;
	}

	if(size) {
		log_.log(logger::debug_trace, "adding {} bytes to buffer for channel id={} [used={}, buffer_size={}]", size, local_info_.id, used_, buffer_.size());
		copy(safe_subspan(data, 0, size), safe_subspan(buffer_, used_, size));
		used_ += size;
	}

	return std::uint32_t(size);
}

std::uint32_t channel::send_data(const_span s) {
	// see if we have something to send already
	do_flush();

	if(state_ >= channel_state::close_pending) {
		// we are closing or already closed, abort sending
		return 0;
	}

	// is there something pending still, just use the buffer
	if(used_) {
		return write_to_buffer(s);
	}

	// see if we can directly send some data
	std::uint32_t pos = 0;
	bool failed_to_alloc = false;
	do {
		std::uint32_t size = std::min(out_window_, std::min(max_out_size_, std::uint32_t(s.size())-pos));

		if(size) {
			auto data_span = safe_subspan(s, pos, size);
			ser::channel_data::save p(remote_info_.id, to_string_view(data_span));

			auto rec = transport_.alloc_out_packet(p.size());
			if(rec) {
				if(!p.write(rec->data) || !transport_.write_alloced_out_packet(*rec)) {
					log_.log(logger::error, "could not serialise packet?!");
					return 0;
				}
				pos += size;
				out_window_ -= size;
			} else {
				failed_to_alloc = true;
			}
		}
	} while(!failed_to_alloc && out_window_ && pos < s.size());

	if(pos < s.size()) {
		pos += write_to_buffer(safe_subspan(s, pos));
	}

	return pos;
}

bool channel::send_subsystem_request(std::string_view subsystem) {
	return transport_.send_packet<ser::channel_subsystem_request>(remote_info_.id, "subsystem", true, subsystem);
}

bool channel::send_eof() {
	return transport_.send_packet<ser::channel_eof>(remote_info_.id);
}

bool channel::send_close() {
	bool res = true;
	if(!sent_close_) {
		if(state_ <= channel_state::close_pending) {
			if(!used_) {
				res = transport_.send_packet<ser::channel_close>(remote_info_.id);
				if(res) {
					sent_close_ = true;
				}
			}

			if(received_close_ && sent_close_) {
				set_state(channel_state::closed);
			} else if(res) {
				set_state(channel_state::close_pending);
			}
		}
	}
	return res;
}

bool channel::send_window_adjust(std::uint32_t n) {
	bool ret = transport_.send_packet<ser::channel_window_adjust>(remote_info_.id, n);
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
	log_.log(logger::info, "channel open id={} ({})", local_info_.id, remote.id);
	remote_info_ = remote;
	out_window_ = remote_info_.window_size;
	max_out_size_ = std::min(remote_info_.max_packet_size, transport_.max_out_packet_size())-packet_overhead;
	set_state(channel_state::established);
	return transport_.send_packet<ser::channel_open_confirmation>(
			remote_info_.id,
			local_info_.id,
			local_info_.window_size,
			local_info_.max_packet_size);
}

bool channel::on_confirm(channel_side_info remote, const_span /*extra_data*/) {
	log_.log(logger::info, "channel open confirmed id={} ({}) [out window={}]", local_info_.id, remote.id, remote.window_size);
	remote_info_ = remote;
	out_window_ = remote_info_.window_size;
	max_out_size_ = std::min(remote_info_.max_packet_size, transport_.max_out_packet_size()-packet_overhead);
	set_state(channel_state::established);
	return true;
}

void channel::on_failure(std::uint32_t code, std::string_view message) {
	set_state(channel_state::closed);
	log_.log(logger::info, "failed to open channel id={} (remote refuses) [code={}, msg={}]", local_info_.id, code, message);
}

bool channel::on_data(const_span d) {
	// just call to adjust window with chosen strategy
	adjust_in_window(std::uint32_t(d.size()));
	return true;
}

bool channel::on_extended_data(std::uint32_t data_type, const_span d) {
	// just call to adjust window with chosen strategy
	adjust_in_window(std::uint32_t(d.size()));
	return true;
}

void channel::on_window_adjust(std::uint32_t bytes) {
	log_.log(logger::debug_trace, "adjusting out window id={} [bytes={}]", local_info_.id, bytes);
	// lets not increase the size over 2^32-1
	out_window_ += std::min(bytes, std::numeric_limits<std::uint32_t>::max() - out_window_);

	//see if we can send something directly
	if(used_) {
		do_flush();
	}

	if(state_ == channel_state::established && used_ < buffer_.size() && out_window_) {
		on_send_more();
	}
}

void channel::on_eof() {
	// nothing here
}

void channel::on_close() {
	log_.log(logger::debug_trace, "received on_close for channel id={}", local_info_.id);
	if(!received_close_) {
		received_close_ = true;
		if(state_ <= channel_state::close_pending) {
			if(sent_close_) {
				set_state(channel_state::closed);
			} else {
				if(used_) {
					//lets wait for flush
					set_state(channel_state::close_pending);
				} else {
					transport_.send_packet<ser::channel_close>(remote_info_.id);
					sent_close_ = true;
					set_state(channel_state::closed);
				}
			}
		}
	}
}

bool channel::send_data_packet() {
	std::uint32_t size = std::min(out_window_, std::min(max_out_size_, used_));
	auto data_span = safe_subspan(buffer_, 0, size);
	ser::channel_data::save packet(remote_info_.id, to_string_view(data_span));
	auto rec = transport_.alloc_out_packet(packet.size());
	bool res(rec);
	if(res) {
		res = packet.write(rec->data) && transport_.write_alloced_out_packet(*rec);
		if(res) {
			if(used_ > size) {
				std::memmove(buffer_.data(), buffer_.data()+size, used_-size);
			}
			used_ -= size;
			out_window_ -= size;
		} else {
			log_.log(logger::debug_trace, "failed to send buffered channel data [channel={}, used={}, size={}, out_window={}]"
				, local_info_.id, used_, size, out_window_);
		}
	}
	return res;
}

bool channel::send_packet(const_span s) {
	// see if we have something to send already
	do_flush();

	if(state_ >= channel_state::close_pending) {
		// we are closing or already closed, abort sending
		return false;
	}

	std::uint32_t max_size = std::min(out_window_, max_out_size_);

	if(used_ || max_size < s.size()) {
		return write_to_buffer(s, false) != 0;
	}

	ser::channel_data::save p(remote_info_.id, to_string_view(s));
	auto rec = transport_.alloc_out_packet(p.size());

	if(p.write(rec->data) && transport_.write_alloced_out_packet(*rec)) {
		out_window_ -= s.size();
		return true;
	}

	return write_to_buffer(s, false) != 0;
}

bool channel::flush() {
	std::uint32_t used_before = used_;
	do_flush();
	if(state_ == channel_state::established && used_ < used_before && out_window_) {
		on_send_more();
	}
	return used_ && out_window_;
}

bool channel::do_flush() {
	log_.log(logger::debug_trace, "trying to flush buffer for channel id={} [used={}, out_window={}]", local_info_.id, used_, out_window_);
	while(used_ && out_window_ && send_data_packet())
	{
	}
	if(!used_ && state_ == channel_state::close_pending) {
		if(!sent_close_) {
			transport_.send_packet<ser::channel_close>(remote_info_.id);
			sent_close_ = true;
		}
		set_state(channel_state::closed);
	}
	return used_ && out_window_;
}


void channel::on_send_more() {
	//nothing here
}

std::unique_ptr<channel_base> channel::on_request(std::string_view name, bool reply, const_span) {
	log_.log(logger::debug_trace, "received channel request [name={}, reply={}]", name, reply);
	if(reply) {
		transport_.send_packet<ser::channel_failure>(remote_info_.id);
	}
	return nullptr;
}

void channel::on_request_success() {
	log_.log(logger::debug_trace, "received channel request success");
}

void channel::on_request_failure() {
	log_.log(logger::debug_trace, "received channel request failure");
}

// default strategy: wait for half of the window and then adjust
void channel::adjust_in_window(std::uint32_t s) {
	// lets not increase the size over 2^32-1
	in_window_ += std::min(s, std::numeric_limits<std::uint32_t>::max() - in_window_);
	if(in_window_ >= remote_info_.window_size/2) {
		log_.log(logger::debug_trace, "adjusting in window [in_window={}, window_size={}]", in_window_, remote_info_.window_size);
		send_window_adjust(in_window_);
	}
}

void channel::set_state(channel_state s) {
	SPSSH_ASSERT(state_ < s, "invalid state change");
	log_.log(logger::debug_trace, "changing state for channel id={} [{} -> {}]", local_info_.id, to_string(state_), to_string(s));
	state_ = s;
	on_state_change();
}

void channel::on_state_change() {
	//nothing here
}

transport_base& channel::transport() const {
	return transport_;
}

}

