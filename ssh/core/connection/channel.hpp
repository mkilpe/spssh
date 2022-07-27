#ifndef SP_SHH_CHANNEL_HEADER
#define SP_SHH_CHANNEL_HEADER

#include "conn_protocol.hpp"

#include "ssh/common/types.hpp"
#include "ssh/core/transport_base.hpp"
#include "ssh/core/packet_ser_impl.hpp"

namespace securepath::ssh {

using channel_id = std::uint32_t;
std::size_t const default_buffer_size{128*1024};

// this is either the local or remote side of the channel
struct channel_side_info {
	channel_id id{};
	std::uint32_t window_size{};
	std::uint32_t max_packet_size{};
};

enum class channel_state {
	init,
	open_pending,  //we have sent open and waiting for open confirmation or failure
	established,   //we have established a connection, data flows
	close_pending, //waiting to close the connection
	closed
};
std::string_view to_string(channel_state);

class channel_base {
public:
	channel_base(channel_id id)
	: id_(id)
	{}

	virtual ~channel_base() = default;

	channel_id id() const { return id_; }
	channel_state state() const { return state_; }

	/// if locally initiating the open, this is called to send the open channel packet
	virtual bool send_open(std::string_view type) = 0;

	/// if remotely initiated, this is called after constructing the channel object, it should send either confirmation or failure for opening
	virtual bool on_open(channel_side_info remote, const_span extra_data) = 0;

	/// if locally initiated, this is called when remote side confirms the channel open
	virtual bool on_confirm(channel_side_info remote, const_span extra_data) = 0;

	/// if locally initiated, this is called when remote side send open failure
	virtual void on_failure(std::uint32_t code, std::string_view message) = 0;

	/// called when data packet is received
	virtual void on_data(const_span) = 0;

	/// called when extended data packet is received
	virtual void on_extended_data(std::uint32_t data_type, const_span) = 0;

	/// called when remote side adjusts our sending window
	virtual void on_window_adjust(std::uint32_t bytes) = 0;

	/// called when remote side sent eof
	virtual void on_eof() = 0;

	/// called when remote side closed the channel
	virtual void on_close() = 0;

	// called when received channel request, return true if handling the message (this also means replying to it)
	virtual void on_request(std::string_view name, bool reply, const_span extra_data) = 0;

	// called for successful response to channel request. The responses for request come in the order the requests were sent.
	virtual void on_request_success() = 0;

	// called for channel response failure
	virtual void on_request_failure() = 0;

	// try to flush out buffer, return true if more still left to be flushed
	virtual bool flush() = 0;

	// something was sent from the internal buffer or out window was adjusted, so more can be send
	virtual void on_send_more() = 0;

protected:
	channel_id const id_;
	channel_state state_{};
};

/// Implements basic channel functionality for easier usage
class channel : public channel_base {
public:
	channel(transport_base& transport, channel_side_info local, std::size_t buffer_size = default_buffer_size);
	~channel();

public: //out
	/// send data packet using binary data, returns the amount of handled bytes
	std::uint32_t send_data(const_span);

	/// send eof packet, after this one should not send anything any more but can receive
	bool send_eof();

	/// send close packet and initiate closing of the channel
	bool send_close();

	//bool send_request(...);

	/// send packet to adjust remote window by n-bytes
	bool send_window_adjust(std::uint32_t n);

	/// send data packet using Packet type and Args to serialise the data
	template<typename Packet, typename... Args>
	bool send_packet(Args&&... args);

protected:
	bool send_open(std::string_view type) override;
	bool on_open(channel_side_info remote, const_span extra_data) override;
	bool on_confirm(channel_side_info remote, const_span extra_data) override;
	void on_failure(std::uint32_t code, std::string_view message) override;
	void on_data(const_span) override;
	void on_extended_data(std::uint32_t data_type, const_span) override;
	void on_window_adjust(std::uint32_t bytes) override;
	void on_eof() override;
	void on_close() override;
	bool flush() override;
	void on_send_more() override;
	void on_request(std::string_view name, bool reply, const_span extra_data) override;
	void on_request_success() override;
	void on_request_failure() override;

	virtual void adjust_in_window(std::uint32_t size);

	void set_state(channel_state);

protected:
	template<typename Packet>
	bool serialise_to_buffer(Packet& p);

	std::uint32_t write_to_buffer(const_span);
	bool send_data_packet();
	bool do_flush();

protected:
	transport_base& transport_;
	logger& log_;

	channel_side_info local_info_;
	channel_side_info remote_info_;
	bool sent_close_{};
	bool received_close_{};

	std::uint32_t max_out_size_{};

	// how much we have window left for sending
	std::uint32_t out_window_{};
	// how much we have received without adjusting
	std::uint32_t in_window_{};

	// out buffer
	byte_vector buffer_;
	// how much we have used the buffer
	std::uint32_t used_{};
};

template<typename Packet>
bool channel::serialise_to_buffer(Packet& p) {
	std::uint32_t p_size = p.size();
	bool res = buffer_.size() - used_ >= p_size;
	if(res) {
		res = p.write(safe_subspan(buffer_, used_, p_size));
		if(res) {
			used_ += p_size;
		}
	}
	return res;
}

template<typename Packet, typename... Args>
bool channel::send_packet(Args&&... args) {
	// see if we have something to send already
	do_flush();

	if(state_ >= channel_state::close_pending) {
		// we are closing or already closed, abort sending
		return false;
	}

	typename Packet::save p(std::forward<Args>(args)...);

	if(used_) {
		return serialise_to_buffer(p);
	}

	std::uint32_t max_size = std::min(out_window_, max_out_size_);

	std::uint32_t p_size = p.size();
	if(max_size < p_size) {
		return serialise_to_buffer(p);
	}

	auto out = make_packet_saver<ser::channel_data>(remote_info_.id, p);
	auto rec = transport_.alloc_out_packet(out.size());

	bool res = out.write(rec->data) && transport_.write_alloced_out_packet(*rec);
	if(res) {
		out_window_ -= p_size;
	} else {
		res = serialise_to_buffer(p);
	}
	return res;
}

}

#endif
