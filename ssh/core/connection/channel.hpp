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

class channel_base {
public:
	channel_base(channel_id id)
	: id_(id)
	{}

	channel_id id() const { return id_; }

	virtual ~channel_base() = default;

	/// if locally initiating the open, this is called to send the open channel packet
	virtual bool send_open(std::string_view type) = 0;

	/// if remotely initiated, this is called after constructing the channel object, it should send either confirmation or failure for opening
	virtual bool on_open(channel_side_info remote, const_span extra_data) = 0;

	/// if locally initiated, this is called when remote side confirms the channel open
	virtual bool on_confirm(const_span extra_data) = 0;

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
	//virtual void on_request(...) = 0;

protected:
	channel_id const id_;
};

/// Implements basic channel functionality for easier usage
class channel : public channel_base {
public:
	channel(transport_base& transport, channel_side_info local, std::size_t buffer_size = default_buffer_size);

public: //out
	/// send data packet using binary data
	bool send_data(const_span);

	/// send extended data packet using binary data
	bool send_extended_data(std::uint32_t data_type, const_span);

	/// send eof packet, after this one should not send anything any more but can receive
	bool send_eof();

	/// send close packet and initiate closing of the channel
	bool send_close();

	//bool send_request(...);

	/// send packet to adjust remote window by n-bytes
	bool send_window_adjust(std::uint32_t n);

	/// send data packet using Packet type and Args to serialise the data
	template<typename Packet, typename... Args>
	bool send_packet(Args&&... args) {
		typename Packet::save inner(std::forward<Args>(args)...);
		auto outer = make_packet_saver<ser::channel_data>(remote_info_.id, inner);
		return write_data(outer, inner.size());
	}

	/// send extended data packet using Packet type and Args to serialise the data
	template<typename Packet, typename... Args>
	bool send_extended_packet(std::uint32_t data_type, Args&&... args) {
		typename Packet::save inner(std::forward<Args>(args)...);
		auto outer = make_packet_saver<ser::channel_extended_data>(remote_info_.id, data_type, inner);
		return write_data(outer, inner.size());
	}

protected:
	bool send_open(std::string_view type) override;
	bool on_open(channel_side_info remote, const_span extra_data) override;
	bool on_confirm(const_span extra_data) override;
	void on_failure(std::uint32_t code, std::string_view message) override;
	void on_data(const_span) override;
	void on_extended_data(std::uint32_t data_type, const_span) override;
	void on_window_adjust(std::uint32_t bytes) override;
	void on_eof() override;
	void on_close() override;
protected:

	template<typename Packet>
	bool write_to_buffer(Packet& packet);

	template<typename Packet>
	bool write_data(Packet& packet, std::size_t data_size);

private:
	transport_base& transport_;

	channel_side_info local_info_;
	channel_side_info remote_info_;

	// how much we have window left for sending
	std::uint32_t out_window_{};
	// how much we have received without adjusting
	std::uint32_t in_window_{};

	// out buffer
	byte_vector buffer_;
	// how much we have used the buffer
	std::size_t used_{};
};

}

#endif
