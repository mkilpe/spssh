#include "ssh_connection.hpp"
#include "conn_protocol.hpp"

#include "ssh/core/transport_base.hpp"
#include "ssh/core/service/names.hpp"

namespace securepath::ssh {

ssh_connection::ssh_connection(transport_base& t)
: transport_(t)
, log_(transport_.log())
, config_(t.config())
{
}

std::string_view ssh_connection::name() const {
	return connection_service_name;
}

service_state ssh_connection::state() const {
	return state_;
}

bool ssh_connection::init() {
	return true;
}

std::unique_ptr<channel_base> ssh_connection::construct_channel(std::string_view type, channel_constructor channel_ctor) {
	std::unique_ptr<channel_base> res;
	if(!channel_ctor) {
		auto it = channel_ctors_.find(type);
		if(it != channel_ctors_.end()) {
			channel_ctor = it->second;
		}
	}
	if(channel_ctor) {
		channel_side_info local{++current_id_, config_.channel.initial_window_size, config_.channel.max_packet_size};
		res = channel_ctor(transport_, std::move(local));
		if(!res) {
			log_.log(logger::info, "failed to construct channel [type={}]", type);
		}
	} else {
		log_.log(logger::info, "unknown channel type [type={}]", type);
	}
	return res;
}

void ssh_connection::add_channel(std::unique_ptr<channel_base> ch) {
	channel_id id = ch->id();
	channels_[id] = std::move(ch);
}

handler_result ssh_connection::handle_open(const_span payload) {
	ser::channel_open::load packet(payload);
	if(packet) {
		auto& [type, sender_channel, initial_window, max_packet] = packet;

		auto ch = construct_channel(type, {});
		if(ch) {
			channel_side_info remote{sender_channel, initial_window, max_packet};
			if(ch->on_open(std::move(remote), safe_subspan(payload, packet.size()))) {
				add_channel(std::move(ch));
			}
		} else {
			transport_.send_packet<ser::channel_open_failure>(sender_channel, ser::unknown_channel_type, "unknown channel type", "");
		}
	} else {
		log_.log(logger::error, "Invalid channel open packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}

	return handler_result::handled;
}

handler_result ssh_connection::handle_open_confirm(const_span payload) {
	ser::channel_open_confirmation::load packet(payload);
	if(packet) {
		auto& [local_id, remote_id, initial_window, max_packet] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			channel_side_info remote{remote_id, initial_window, max_packet};
			if(!it->second->on_confirm(std::move(remote), safe_subspan(payload, packet.size()))) {
				//t: what to send here? a close packet?
				channels_.erase(it);
			}
		} else {
			log_.log(logger::error, "Invalid channel id with open confirmation [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel open confirmation packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_open_failure(const_span payload) {
	ser::channel_open_failure::load packet(payload);
	if(packet) {
		auto& [local_id, code, message, lang] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			it->second->on_failure(code, message);
			channels_.erase(it);
		} else {
			log_.log(logger::error, "Invalid channel id with open failure [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel open failure packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_close(const_span payload) {
	ser::channel_close::load packet(payload);
	if(packet) {
		auto& [local_id] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			it->second->on_close();
			if(it->second->state() == channel_state::closed) {
				channels_.erase(it);
			}
		} else {
			log_.log(logger::error, "Invalid channel id with open failure [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel open failure packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_global_request(const_span payload) {
	ser::global_request::load packet(payload);
	if(packet) {
		auto& [request_name, reply] = packet;
		if(!on_global_request(request_name, reply, safe_subspan(payload, packet.size()))) {
			if(reply) {
				transport_.send_packet<ser::request_failure>();
			}
		}
	} else {
		log_.log(logger::error, "Invalid global request packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_request_success(const_span payload) {
	ser::request_success::load packet(payload);
	if(packet) {
		on_request_success(safe_subspan(payload, packet.size()));
	} else {
		log_.log(logger::error, "Invalid global request success packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_request_failure(const_span payload) {
	ser::request_success::load packet(payload);
	if(packet) {
		on_request_failure();
	} else {
		log_.log(logger::error, "Invalid global request failure packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_window_adjust(const_span payload) {
	ser::channel_window_adjust::load packet(payload);
	if(packet) {
		auto& [local_id, bytes] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			it->second->on_window_adjust(bytes);
		} else {
			log_.log(logger::error, "Invalid channel id with window adjust [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel window adjust packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_data(const_span payload) {
	ser::channel_data::load packet(payload);
	if(packet) {
		auto& [local_id, data] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			if(!it->second->on_data(to_span(data))) {
				log_.log(logger::debug_trace, "on_data returned false [id={}]", local_id);
				return handler_result::pending;
			}
		} else {
			log_.log(logger::error, "Invalid channel id with data [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel data packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_extended_data(const_span payload) {
	ser::channel_extended_data::load packet(payload);
	if(packet) {
		auto& [local_id, type, data] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			it->second->on_extended_data(type, to_span(data));
		} else {
			log_.log(logger::error, "Invalid channel id with extended data [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel extended data packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_eof(const_span payload) {
	ser::channel_eof::load packet(payload);
	if(packet) {
		auto& [local_id] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			it->second->on_eof();
		} else {
			log_.log(logger::error, "Invalid channel id with eof [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel eof packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_channel_request(const_span payload) {
	ser::channel_request::load packet(payload);
	if(packet) {
		auto& [local_id, name, reply] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			auto new_chan = it->second->on_request(name, reply, safe_subspan(payload, packet.size()));
			if(new_chan) {
				log_.log(logger::debug_trace, "Upgrading channel [id={}]", local_id);
				std::swap(it->second, new_chan);
			}
		} else {
			log_.log(logger::error, "Invalid channel id with channel request [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel request packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_channel_success(const_span payload) {
	ser::channel_success::load packet(payload);
	if(packet) {
		auto& [local_id] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			it->second->on_request_success();
		} else {
			log_.log(logger::error, "Invalid channel id with channel request success [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel request success packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::handle_channel_failure(const_span payload) {
	ser::channel_failure::load packet(payload);
	if(packet) {
		auto& [local_id] = packet;
		auto it = channels_.find(local_id);
		if(it != channels_.end()) {
			it->second->on_request_failure();
		} else {
			log_.log(logger::error, "Invalid channel id with channel request failure [id={}]", local_id);
		}
	} else {
		log_.log(logger::error, "Invalid channel request failure packet");
		transport_.set_error_and_disconnect(ssh_protocol_error);
	}
	return handler_result::handled;
}

handler_result ssh_connection::process(ssh_packet_type type, const_span payload) {
	switch(type) {
		case ssh_channel_open :              return handle_open(payload);
		case ssh_channel_open_confirmation : return handle_open_confirm(payload);
		case ssh_channel_open_failure :      return handle_open_failure(payload);
		case ssh_channel_close :             return handle_close(payload);
		case ssh_global_request :            return handle_global_request(payload);
		case ssh_request_success :           return handle_request_success(payload);
		case ssh_request_failure :           return handle_request_failure(payload);
		case ssh_channel_window_adjust :     return handle_window_adjust(payload);
		case ssh_channel_data :              return handle_data(payload);
		case ssh_channel_extended_data :     return handle_extended_data(payload);
		case ssh_channel_eof :               return handle_eof(payload);
		case ssh_channel_request :           return handle_channel_request(payload);
		case ssh_channel_success :           return handle_channel_success(payload);
		case ssh_channel_failure :           return handle_channel_failure(payload);
		default: break; // to suppress warning
	};

	log_.log(logger::error, "Unknown packet type for ssh_connection [type={}]", int(type));

	return handler_result::unknown;
}

bool ssh_connection::flush() {
	bool more = false;
	// in case the channel reports there are more data still, we probably fully filled the out buffers and give up
	for(auto it = channels_.begin(); !more && it != channels_.end(); ) {
		channel_base& c = *it->second;
		if(c.state() == channel_state::established || c.state() == channel_state::close_pending) {
			more = c.flush();
		}
		if(c.state() == channel_state::closed) {
			it = channels_.erase(it);
		} else {
			++it;
		}
	}
	return more;
}

void ssh_connection::add_channel_type(std::string_view type, channel_constructor ctor) {
	channel_ctors_[std::string(type)] = std::move(ctor);
}

channel_base* ssh_connection::open_channel(std::string_view type, channel_constructor channel_ctor) {
	channel_base* res{};
	auto ch = construct_channel(type, std::move(channel_ctor));
	if(ch) {
		if(ch->send_open(type)) {
			res = ch.get();
			add_channel(std::move(ch));
		}
	}
	return res;
}

channel_base* ssh_connection::find_channel(channel_id id) const {
	auto it = channels_.find(id);
	return it != channels_.end() ? it->second.get() : nullptr;
}

bool ssh_connection::on_global_request(std::string_view name, bool reply, const_span) {
	log_.log(logger::debug_trace, "received global request '{}' [reply={}]", name, reply);
	return false;
}

void ssh_connection::on_request_success(const_span) {
	log_.log(logger::debug_trace, "received global request success");
}

void ssh_connection::on_request_failure() {
	log_.log(logger::debug_trace, "received global request failure");
}

}
