#ifndef SPSSH_CORE_KEX_DIFFIE_HELLMAN_HEADER
#define SPSSH_CORE_KEX_DIFFIE_HELLMAN_HEADER

#include "dh.hpp"
#include "kex_common.hpp"

namespace securepath::ssh {

struct diffie_hellman_kex_client : public kex_common {
	diffie_hellman_kex_client(kex_context kex_c, kex_type type)
	: kex_common(kex_c, type)
	{
		context_.logger().log(logger::debug_trace, "constructing diffie_hellman_kex_client");
	}

	kex_state initiate() override {
		if(exchange_) {
			if(context_.send_packet<ser::kexdh_init>(to_umpint(exchange_->public_key()))) {
				return set_state(kex_state::inprogress);
			}
		}
		set_error(ssh_key_exchange_failed, "Failed to initiate kex");
		return kex_state::error;
	}

	kex_state handle(ssh_packet_type type, const_span payload) override {
		if(state_ != kex_state::inprogress) {
			set_error(ssh_key_exchange_failed, "Invalid state");
			return kex_state::error;
		}

		if(type == ssh_packet_type(ssh_kexdh_reply)) {
			ser::kexdh_reply::load packet(ser::match_type_t, payload);
			if(packet) {
				auto & [host_key, server_eph_key, sig] = packet;

				auto secret = exchange_->agree(server_eph_key.data);

				if(is_zero(secret)) {
					set_error(ssh_key_exchange_failed, "Invalid shared secret");
					return kex_state::error;
				}

				auto host_key_span = to_span(host_key);
				auto hash = calculate_exchange_hash(host_key_span, server_eph_key, secret);
				if(hash.empty()) {
					set_error(ssh_key_exchange_failed, "Failed to calculate exchange hash");
					return kex_state::error;
				}

				ssh_public_key hkey = load_ssh_public_key(host_key_span, context_.ccontext(), context_.call_context());
				if(!hkey.valid()) {
					set_error(ssh_key_exchange_failed, "Failed to load server host key");
					return kex_state::error;
				}

				if(!hkey.verify(hash, to_span(sig))) {
					set_error(ssh_key_exchange_failed, "Failed to verify signature");
					return kex_state::error;
				}

				set_data(std::move(hash), std::move(secret), byte_vector(host_key_span.begin(), host_key_span.end()));
				return set_state(kex_state::succeeded);
			} else {
				set_error(ssh_key_exchange_failed, "Invalid kex packet");
			}
		} else {
			set_error(ssh_key_exchange_failed, "Wrong kex packet [type={}]", type);
		}
		return kex_state::error;
	}

};

struct diffie_hellman_kex_server : public kex_common {
	diffie_hellman_kex_server(kex_context kex_c, kex_type type)
	: kex_common(kex_c, type)
	{
		context_.logger().log(logger::debug_trace, "constructing diffie_hellman_kex_server");
	}

	kex_state initiate() override {
		if(exchange_) {
			return set_state(kex_state::inprogress);
		}
		set_error(ssh_key_exchange_failed, "Failed to construct kex");
		return kex_state::error;
	}

	kex_state handle(ssh_packet_type type, const_span payload) override {
		if(state_ != kex_state::inprogress) {
			set_error(ssh_key_exchange_failed, "Invalid state");
			return kex_state::error;
		}
		if(type == ssh_packet_type(ssh_kexdh_init)) {
			ser::kexdh_init::load packet(ser::match_type_t, payload);
			if(packet) {
				auto & [client_key] = packet;

				auto secret = exchange_->agree(client_key.data);

				if(is_zero(secret)) {
					set_error(ssh_key_exchange_failed, "Invalid shared secret");
					return kex_state::error;
				}

				return send_reply(client_key, std::move(secret));
			} else {
				set_error(ssh_key_exchange_failed, "Invalid kex packet");
			}
		} else {
			set_error(ssh_key_exchange_failed, "Wrong kex packet [type={}]", type);
		}
		return kex_state::error;
	}

	kex_state send_reply(const_mpint_span client_key, byte_vector secret) {
		auto it = std::find_if(context_.config().private_keys.begin(),
							context_.config().private_keys.end(),
							[&](auto&& v) { return v.key.type() == conf_.host_key; });

		if(it == context_.config().private_keys.end()) {
			set_error(ssh_key_exchange_failed, "Failed to find suitable host key");
			return kex_state::error;
		}

		auto hash = calculate_exchange_hash(it->ser_pubkey, client_key, secret);
		if(hash.empty()) {
			set_error(ssh_key_exchange_failed, "Failed to calculate exchange hash");
			return kex_state::error;
		}

		byte_vector sig = it->key.sign(hash);
		if(sig.empty()) {
			set_error(ssh_key_exchange_failed, "Failed to sign exchange hash");
			return kex_state::error;
		}

		if(!context_.send_packet<ser::kexdh_reply>(
			to_string_view(it->ser_pubkey),
			to_umpint(exchange_->public_key()),
			to_string_view(sig)))
		{
			set_error(ssh_key_exchange_failed, "Failed to create reply packet");
			return kex_state::error;
		}

		set_data(std::move(hash), std::move(secret), it->ser_pubkey);
		return set_state(kex_state::succeeded);
	}

};

}

#endif