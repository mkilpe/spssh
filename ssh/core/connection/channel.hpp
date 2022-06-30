#ifndef SP_SHH_CHANNEL_HEADER
#define SP_SHH_CHANNEL_HEADER

#include "ssh/common/types.hpp"
#include "ssh/core/transport_base.hpp"

namespace securepath::ssh {

using channel_id = std::uint32_t;

class channel_base {
public:
	virtual ~channel_base() = default;

	virtual void on_data(const_span) = 0;
	virtual void on_extended_data(const_span) = 0;
	virtual void on_eof() = 0;
	virtual void on_close() = 0;
	//virtual void on_request(...) = 0;
};

class channel : public channel_base {
public:
	channel(transport_base& transport);

public: //out
	/// send data packet using binary data
	bool send_data(const_span);

	/// send extended data packet using binary data
	bool send_extended_data(const_span);

	/// send eof packet, after this one should not send anything any more but can receive
	bool send_eof();

	/// send close packet and initiate closing of the channel
	bool send_close();

	//bool send_request(...);

	/// send packet to adjust remote window by n-bytes
	bool send_window_adjust(std::uint32_t n);

	/// send data packet using Packet type and Args to serialise the data
	template<typename Packet, typename... Args>
	bool send_packet(Args const&... args) {
		return false;
	}

	/// send extended data packet using Packet type and Args to serialise the data
	template<typename Packet, typename... Args>
	bool send_extended_packet(Args const&... args) {
		return false;
	}

private:
	transport_base& transport_;
	channel_id sender_channel_{};
	channel_id recipient_channel_{};
	// how much we have window left for sending
	std::uint32_t out_window_{};
	// how much we have received without adjusting
	std::uint32_t in_window_{};
	std::uint32_t max_packet_size_{}

	// out buffer
	byte_vector buffer_;
	// how much we have used the buffer
	std::size_t used_{};
};

}

#endif
