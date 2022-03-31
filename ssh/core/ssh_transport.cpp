
#include "kex.hpp"
#include "ssh_transport.hpp"
#include "protocol_helpers.hpp"
#include "protocol.hpp"
#include "packet_ser_impl.hpp"

#include <ostream>

namespace securepath::ssh {

char const* const state_strings[] =
	{ "none"
	, "version_exchange"
	, "kex"
	, "transport"
	, "user_authentication"
	, "subsystem"
	, "disconnected"
	};

std::string_view to_string(ssh_state s) {
	return state_strings[std::size_t(s)];
}

std::ostream& operator<<(std::ostream& out, ssh_state state) {
	return out << to_string(state);
}

ssh_transport::ssh_transport(ssh_config const& c, logger& l, out_buffer& out, crypto_context cc)
: ssh_binary_packet(c, l)
, crypto_(std::move(cc))
, output_(out)
, rand_(crypto_.construct_random())
{
	if(rand_) {
		set_random(*rand_);
	} else {
		logger_.log(logger::error, "SSH Unable to create random generator, double check your set-up");
		set_state(ssh_state::disconnected, spssh_invalid_setup);
	}
}

ssh_transport::~ssh_transport()
{
}

void ssh_transport::on_version_exchange(ssh_version const& v) {
	logger_.log(logger::info, "SSH version exchange [remote ssh={}, remote software={}]", v.ssh, v.software);

	if(v.ssh != "2.0") {
		logger_.log(logger::error, "SSH invalid remote version [{} != 2.0]", v.ssh);
		//unsupported version
		set_error_and_disconnect(ssh_protocol_version_not_supported);
	}
}

ssh_state ssh_transport::state() const {
	return state_;
}

void ssh_transport::set_state(ssh_state s, std::optional<ssh_error_code> err) {
	SPSSH_ASSERT(state_ != ssh_state::disconnected, "already in disconnected state");
	if(err) {
		set_error(*err);
	}
	//t: debug check for state changes
	state_ = s;
}

void ssh_transport::disconnect(std::uint32_t code, std::string_view message) {
	logger_.log(logger::debug, "SSH disconnect [state={}, code={}, msg={}]", to_string(state()), code, message);

	if(state() != ssh_state::none && state() != ssh_state::disconnected) {
		send_packet<ser::disconnect>(code, message, "");
	}
	set_state(ssh_state::disconnected);
}

void ssh_transport::set_error_and_disconnect(ssh_error_code code) {
	logger_.log(logger::debug_trace, "SSH setting error [error={}]", code);
	SPSSH_ASSERT(error_ == ssh_noerror, "already error set");
	error_ = code;
	disconnect(code);
}

void ssh_transport::handle_version_exchange(in_buffer& in) {
	logger_.log(logger::debug_trace, "SSH handle_version_exchange [state={}]", to_string(state()));
	if(state() == ssh_state::none) {
		if(!send_version_string(config_.my_version, output_)) {
			set_state(ssh_state::disconnected);
		} else {
			set_state(ssh_state::version_exchange);
		}
	}
	if(state() == ssh_state::version_exchange) {
		if(!remote_version_received_) {
			auto res = parse_ssh_version(in, false, kex_data_.remote_ver);
			if(res == version_parse_result::ok) {
				remote_version_received_ = true;
				on_version_exchange(kex_data_.remote_ver);
				if(error_ == ssh_noerror) {
					kex_data_.local_ver = config_.my_version;
					set_state(ssh_state::kex);
				}
			} else if(res == version_parse_result::error) {
				set_error(ssh_protocol_error, "failed to parse protocol version information");
				set_state(ssh_state::disconnected);
			} else {
				logger_.log(logger::debug_trace, "parse_ssh_version requires more data [in_buffer.size={}]", in.get().size());
			}
		}
	}
}

void ssh_transport::handle_binary_packet(in_buffer& in) {
	auto data = in.get();

	if(stream_in_.current_packet.status == in_packet_status::waiting_header) {
		try_decode_header(data);
	}

	if(stream_in_.current_packet.status == in_packet_status::waiting_data) {
		// see if we have whole packet already
		if(stream_in_.current_packet.packet_size <= data.size()) {
			decrypt_packet(data, data);
		}
	}

	if(stream_in_.current_packet.status == in_packet_status::data_ready) {
		if(process_transport_payload(stream_in_.current_packet.payload)) {
			in.consume(stream_in_.current_packet.packet_size);
			stream_in_.current_packet.clear();
		}
	}
}

transport_op ssh_transport::process(in_buffer& in) {
	// we try to write even in case of disconnect (maybe we want to send disconnect packet)
	if(!send_pending(output_)) {
		return transport_op::want_write_more;
	}

	if(state() == ssh_state::disconnected) {
		return transport_op::disconnected;
	}

	if(state() == ssh_state::none || state() == ssh_state::version_exchange) {
		handle_version_exchange(in);
		// if version exchange is done, start kex
		if(state() == ssh_state::kex) {
			if(!send_kex_init(config_.guess_kex_packet)) {
				return transport_op::disconnected;
			}
		}
	} else {
		handle_binary_packet(in);
	}

	if(!stream_out_.data.empty()) {
		return transport_op::want_write_more;
	} else if(state() == ssh_state::disconnected) {
		return transport_op::disconnected;
	}

	return transport_op::want_read_more;
}

bool ssh_transport::process_transport_payload(span payload) {
	SPSSH_ASSERT(payload.size() >= 1, "invalid payload size");
	ssh_packet_type type = ssh_packet_type(std::to_integer<std::uint8_t>(payload[0]));
	logger_.log(logger::debug, "SSH process_transport_packet [type={}]", type);

	// first see if it is basic packet, we handle these at all states
	bool res = handle_basic_packets(type, payload.subspan(1));

	if(!res) {
		if(state() == ssh_state::kex) {
			// give whole payload as we need to save it for kex
			res = handle_raw_kex_packet(type, payload);
		} else {
			logger_.log(logger::debug, "SSH Unknown packet type, sending unimplemented packet [type={}]", type);
			send_packet<ser::unimplemented>(stream_in_.current_packet.sequence);
			res = true;
		}
	}

	return res;
}

bool ssh_transport::handle_basic_packets(ssh_packet_type type, const_span payload) {
	bool ret = true;
	if(type == ssh_disconnect) {
		ser::disconnect::load packet(payload);
		if(packet) {
			auto & [code, desc, ignore] = packet;
			error_ = ssh_error_code(code);
			error_msg_ = desc;
			logger_.log(logger::info, "SSH Disconnect from remote [code={}, msg={}]", error_, error_msg_);
		} else {
			logger_.log(logger::debug, "SSH Invalid disconnect packet from remote");
			set_error(ssh_protocol_error);
		}
		set_state(ssh_state::disconnected);
	} else if(type == ssh_ignore) {
		ser::ignore::load packet(payload);
		if(packet) {
			logger_.log(logger::debug_trace, "SSH ignore packet received");
		} else {
			logger_.log(logger::debug_trace, "SSH received invalid ignore packet");
			set_error_and_disconnect(ssh_protocol_error);
		}
	} else if(type == ssh_unimplemented) {
		ser::unimplemented::load packet(payload);
		if(packet) {
			auto & [seq] = packet;
			logger_.log(logger::debug, "SSH unimplemented packet received [seq={}]", seq);
		} else {
			logger_.log(logger::debug_trace, "SSH received invalid unimplemented packet");
			set_error_and_disconnect(ssh_protocol_error);
		}
	} else if(type == ssh_debug) {
		ser::debug::load packet(payload);
		if(packet) {
			auto & [always_display, message, lang] = packet;
			logger_.log(logger::debug, "SSH debug packet received [always_display={}, message={}, lange={}]", always_display, message, lang);
		} else {
			logger_.log(logger::debug_trace, "SSH received invalid debug packet");
			set_error_and_disconnect(ssh_protocol_error);
		}
	} else {
		ret = false;
	}

	return ret;
}

template<typename Packet, typename... Args>
bool ssh_transport::send_packet(Args&&... args) {
	logger_.log(logger::debug_trace, "SSH sending packet [type={}]", Packet::packet_type);
	return ssh::send_packet<Packet>(*this, output_, std::forward<Args>(args)...);
}

bool ssh_transport::send_kex_init(bool send_first_packet) {
	logger_.log(logger::debug_trace, "SSH send_kex_init [send guess={}]", send_first_packet);
	SPSSH_ASSERT(!kex_, "invalid state");

	if(config_.algorithms.kexes.empty()) {
		logger_.log(logger::error, "SSH No kex algorithms set, aborting...");
		set_error_and_disconnect(ssh_key_exchange_failed);
		return false;
	}

	kex_cookie_.resize(cookie_size);
	rand_->random_bytes(kex_cookie_);

	bool ret = ser::serialise_to_vector<ser::kexinit>(kex_data_.local_kexinit,
		std::span<std::byte const, cookie_size>(kex_cookie_),
		config_.algorithms.kexes.name_list(),
		config_.algorithms.host_keys.name_list(),
		config_.algorithms.client_server_ciphers.name_list(),
		config_.algorithms.server_client_ciphers.name_list(),
		config_.algorithms.client_server_macs.name_list(),
		config_.algorithms.server_client_macs.name_list(),
		config_.algorithms.client_server_compress.name_list(),
		config_.algorithms.server_client_compress.name_list(),
		std::vector<std::string_view>(), //languages client to server
		std::vector<std::string_view>(), //languages server to client
		send_first_packet,
		0   // reserved for future use
		);

	if(ret) {
		ret = send_payload(*this, kex_data_.local_kexinit, output_);
	}

	if(ret) {
		if(send_first_packet) {
			send_kex_guess();
		}
	}

	return ret;
}

void ssh_transport::send_kex_guess() {
	logger_.log(logger::debug_trace, "SSH send_kex_guess");

	kex_ = construct_kex(config_.side, config_.algorithms.kexes.preferred(),
		kex_context{
			config_,
			*this,
			output_,
			kex_data_,
			crypto_,
			crypto_call_context{logger_, *rand_}});

	kex_->initiate();
}

bool ssh_transport::handle_raw_kex_packet(ssh_packet_type type, const_span payload) {
	logger_.log(logger::debug_trace, "SSH handle_raw_kex_packet [type={}]", type);

	if(kexinit_received_) {
		// see if we need to ignore initial guess
		if(ignore_next_kex_packet_) {
			ignore_next_kex_packet_ = false;
			logger_.log(logger::debug_trace, "SSH ignoring kex packet [type={}]", type);
			return true;
		}
		return handle_kex_packet(type, payload);
	} else {
		// not yet received, so this must be it
		if(type != ssh_kexinit) {
			logger_.log(logger::error, "SSH Received packet other than kexinit [type={}]", type);
			set_error_and_disconnect(ssh_key_exchange_failed);
			return false;
		}

		return handle_kexinit_packet(payload);
	}
}

bool ssh_transport::handle_kex_packet(ssh_packet_type type, const_span payload) {
	if(kex_) {
		kex_->handle(type, payload); // todo: handle return type
		return true;
	} else {
		set_error_and_disconnect(ssh_key_exchange_failed);
		return false;
	}
}

bool ssh_transport::handle_kexinit_packet(const_span payload) {
	logger_.log(logger::debug_trace, "SSH handle_kexinit_packet");

	ser::kexinit::load packet(ser::match_type_t, payload);
	if(!packet) {
		set_error_and_disconnect(ssh_key_exchange_failed);
		logger_.log(logger::error, "SSH Invalid kexinit packet from remote");
		return false;
	}

	auto & [
		kex_cookie,
		kexes,
		host_keys,
		client_server_ciphers,
		server_client_ciphers,
		client_server_macs,
		server_client_macs,
		client_server_compress,
		server_client_compress,
		lang_client_server,
		lang_server_client,
		sent_first_packet,
		reserved
			] = packet;

	//do some sanity checks
	if(kexes.empty()
		|| host_keys.empty()
		|| client_server_ciphers.empty()
		|| server_client_ciphers.empty()
		|| client_server_macs.empty()
		|| server_client_macs.empty()
		|| client_server_compress.empty()
		|| server_client_compress.empty())
	{
		set_error_and_disconnect(ssh_key_exchange_failed);
		logger_.log(logger::error, "SSH Invalid kexinit packet from remote");
		return false;
	}

	supported_algorithms remote_algs{
			algo_list_from_string_list<kex_type>(kexes),
			algo_list_from_string_list<key_type>(host_keys),
			algo_list_from_string_list<cipher_type>(client_server_ciphers),
			algo_list_from_string_list<cipher_type>(server_client_ciphers),
			algo_list_from_string_list<mac_type>(client_server_macs),
			algo_list_from_string_list<mac_type>(server_client_macs),
			algo_list_from_string_list<compress_type>(client_server_compress),
			algo_list_from_string_list<compress_type>(server_client_compress)};

	if(!remote_algs.valid()) {
		set_error_and_disconnect(ssh_key_exchange_failed);
		logger_.log(logger::error, "SSH Invalid kexinit packet from remote");
		return false;
	}

	kexinit_agreement kagree(logger_, config_.side, config_.algorithms);
	if(kagree.agree(remote_algs)) {
		auto crypto_conf = kagree.agreed_configuration();

		logger_.log(logger::debug, "SSH kexinit agreed on configuration [{}]", crypto_conf);

		if(!kagree.was_guess_correct()) {
			// wrong guess, ignore if first packet sent and reset our kex
			ignore_next_kex_packet_ = sent_first_packet;
			kex_.reset();
		}

		// copy the remote kexinit packet for the kex to use for signature
		kex_data_.remote_kexinit = std::vector<std::byte>{payload.begin(), payload.end()};

		if(!kex_) {
			kex_ = construct_kex(config_.side, crypto_conf.kex,
				kex_context{
					config_,
					*this,
					output_,
					kex_data_,
					crypto_,
					crypto_call_context{logger_, *rand_}});

			kex_->initiate();
		}
		kex_->set_crypto_configuration(crypto_conf);
		return true;
	}

	set_error_and_disconnect(ssh_key_exchange_failed);
	logger_.log(logger::debug, "SSH kexinit failed, no mathing algorithms found");
	return false;
}

}