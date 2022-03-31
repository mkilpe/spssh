#ifndef SP_SHH_BINARY_PACKET_HEADER
#define SP_SHH_BINARY_PACKET_HEADER

#include "ssh_config.hpp"
#include "errors.hpp"
#include "packet_types.hpp"
#include "ssh/common/buffers.hpp"
#include "ssh/common/logger.hpp"
#include "ssh_constants.hpp"
#include "ssh/crypto/cipher.hpp"
#include "ssh/crypto/mac.hpp"
#include "ssh/crypto/random.hpp"

#include <cstring>
#include <optional>
#include <memory>
#include <vector>

namespace securepath::ssh {

/// Necessary crypto components and buffers for single stream (i.e. one direction communication)
struct stream_crypto {
	/// sequence number of packet, incremented after every binary protocol packet
	std::uint32_t packet_sequence{};
	std::uint32_t block_size{minimum_block_size};

	std::unique_ptr<ssh::cipher> cipher;
	// this is only used if !cipher->is_aead()
	std::unique_ptr<ssh::mac> mac;

	// this is mac->size() or aead_cipher->tag_size() when we are encrypting, otherwise 0
	std::uint32_t integrity_size{};

	// bytes that has been transferred
	std::uint64_t transferred_bytes{};
};

/// status of incoming packet that is currently being handled
enum class in_packet_status {
	waiting_header, // we have no data or not enough for first block
	waiting_data,   // we have decrypted first block (or we use aead) and know the packet length
	data_ready      // we have decrypted whole packet and ready to process it
};

struct in_packet_info {
	in_packet_status status{in_packet_status::waiting_header};
	std::size_t packet_size{}; // size of the whole packet, this is available after decrypting the header
	std::size_t data_size{};   // size of the transport payload, this is available after decrypting whole packet
	span payload{};            // current decrypted payload to be handled
	std::uint32_t sequence{};  // sequence number of the incoming packet

	void clear() {
		status = in_packet_status::waiting_header;
		packet_size = 0;
		data_size = 0;
		payload = {};
		sequence = 0;
	}
};

struct stream_in_crypto : public stream_crypto {
	in_packet_info current_packet;
	// buffer for calculating tag, should be always integrity_size
	std::vector<std::byte> tag_buffer;
};

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

struct stream_out_crypto : public stream_crypto {
	// buffer for output data, contains the encrypted ready packet to be send
	std::vector<std::byte> buffer;
	// the unhandled portion of buffer, always from the start of the buffer
	span data;
};

class ssh_binary_packet {
public:
	ssh_binary_packet(ssh_config const& config, logger& logger);

	ssh_error_code error() const;
	std::string error_message() const;

	void set_error(ssh_error_code code, std::string_view message = {});

public: //input
	void set_random(random&);
	bool set_input_crypto(std::unique_ptr<ssh::cipher> cipher, std::unique_ptr<ssh::mac> mac);
	bool try_decode_header(span in_data);
	span decrypt_packet(const_span in_data, span out_data);

public: //output
	std::optional<out_packet_record> alloc_out_packet(std::size_t data_size, out_buffer&);
	bool create_out_packet(out_packet_record const&, out_buffer&);

	/// try to send pending data out from the buffers
	bool send_pending(out_buffer&);

protected: //input
	span decrypt_aead(aead_cipher& cip, const_span data, span out);
	span decrypt_with_mac(const_span data, span out);

protected: //output
	std::size_t minimum_padding(std::size_t header_payload_size) const;
	void aead_encrypt(aead_cipher& cip, const_span data, span out);
	void encrypt_with_mac(const_span data, span out);
	void encrypt_packet(const_span data, span out);

private:
	bool resize_out_buffer(std::size_t);
	void shrink_out_buffer();

protected:
	template<typename Packet, typename... Args>
	friend bool send_packet(ssh_binary_packet&, out_buffer&, Args&&...);
	friend bool send_payload(ssh_binary_packet& bp, std::vector<std::byte> const& payload, out_buffer& out);

	ssh_config const& config_;
	logger& logger_;
	random* random_{};

	ssh_error_code error_{};
	std::string error_msg_;

	stream_in_crypto  stream_in_;
	stream_out_crypto stream_out_;
};

template<typename Packet, typename... Args>
bool send_packet(ssh_binary_packet& bp, out_buffer& out, Args&&... args) {
	typename Packet::save packet(std::forward<Args>(args)...);
	std::size_t size = packet.size();

	auto rec = bp.alloc_out_packet(size, out);

	if(rec && packet.write(rec->data)) {
		return bp.create_out_packet(*rec, out);
	} else {
		bp.set_error(spssh_memory_error, "Could not allocate buffer for sending packet");
	}

	return false;
}

bool send_payload(ssh_binary_packet& bp, std::vector<std::byte> const& payload, out_buffer& out);

}

#endif