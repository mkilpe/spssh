#ifndef SP_SSH_TRANSPORT_BASE_HEADER
#define SP_SSH_TRANSPORT_BASE_HEADER

#include "ssh_config.hpp"
#include "ssh/common/types.hpp"
#include "ssh/crypto/crypto_context.hpp"

namespace securepath::ssh {

/// internal type to hold allocated space information when sending packet
struct out_packet_record {
	// size of the whole packet with padding and integrity
	std::size_t size{};
	// size of the payload
	std::size_t payload_size{};
	// size of the random padding
	std::size_t padding_size{};
	// this is where the payload is written to, sub-span of data_buffer
	span data;
	// buffer for the whole transport packet
	span data_buffer;
	// if this record is in-place allocated
	bool inplace{};
};

/// common interface for ssh transport that can be used in services et al
class transport_base {
public:
	virtual ~transport_base() = default;

	virtual ssh_error_code error() const = 0;
	virtual std::string error_message() const = 0;
	virtual void set_error(ssh_error_code code, std::string_view message = {}) = 0;

	/// set error and send disconnect packet with the error in it
	virtual void set_error_and_disconnect(ssh_error_code, std::string_view message = {}) = 0;

	virtual ssh_config const& config() const = 0;
	virtual crypto_context const& crypto() const = 0;
	virtual crypto_call_context call_context() const = 0;

	/// allocate space in buffer to send packet with certain size
	virtual std::optional<out_packet_record> alloc_out_packet(std::size_t data_size) = 0;
	/// write the allocated packet to buffer, must pass out_packet_record returned by alloc_out_packet
	virtual bool write_alloced_out_packet(out_packet_record const&) = 0;

	/// if the session id is set, this will return it, otherwise empty span
	virtual const_span session_id() const = 0;

	/// maximum size of incoming packet (excluding the header, padding and mac)
	virtual std::uint32_t max_in_packet_size() = 0;
	/// maximum size of outgoing packet (excluding the header, padding and mac)
	virtual std::uint32_t max_out_packet_size() = 0;

	template<typename Packet, typename... Args>
	bool send_packet(Args&&... args) {
		call_context().log.log(logger::debug_trace, "SSH sending packet [type={}]", int(Packet::packet_type));

		typename Packet::save packet(std::forward<Args>(args)...);

		auto rec = alloc_out_packet( packet.size());

		if(rec && packet.write(rec->data)) {
			return write_alloced_out_packet(*rec);
		} else {
			set_error(spssh_memory_error, "Could not allocate buffer for sending packet");
		}

		return false;
	}

	bool send_payload(const_span payload);
	logger& log() { return call_context().log; }
};

}

#endif
