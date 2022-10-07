
#include "events.hpp"
#include "ssh_client.hpp"
#include "ssh/core/connection/ssh_connection.hpp"
#include "ssh/core/kex.hpp"
#include "ssh/services/sftp/sftp.hpp"
#include "ssh/services/sftp/sftp_client.hpp"

#include <iostream>
#include <syncstream>

namespace securepath::ssh {

ssh_test_client::ssh_test_client(event_handler& handler, test_client_config const& conf, logger& log, out_buffer& buf, crypto_context c)
: ssh_client(conf, log, buf, c)
, handler_(handler)
, test_config_(conf)
{
}

sftp::sftp_client* ssh_test_client::sftp() {
	sftp::sftp_client* p{};
	if(service_ && channel_id_) {
		auto chan = static_cast<ssh_connection&>(*service_).find_channel(channel_id_);
		if(chan) {
			p = dynamic_cast<sftp::sftp_client*>(chan);
		}
	}
	return p;
}

void ssh_test_client::on_service_started() {
	if(service_->name() == connection_service_name) {
		// connection service started, opening channel
		logger_.log(logger::info, "opening channel: {}", test_config_.channel);

		auto ch = static_cast<ssh_connection&>(*service_)
			.open_channel(test_config_.channel,
					[&](transport_base& t, channel_side_info sinfo) {
					// create shared_ptr that doesn't delete
					std::shared_ptr<sftp::sftp_client_callback> p{this, [](void*){}};
					return std::make_unique<sftp::sftp_client>(p, t, sinfo);
				});

		if(ch) {
			channel_id_ = ch->id();
			logger_.log(logger::debug_trace, "channel id is {}", channel_id_);
		} else {
			logger_.log(logger::error, "failed to open channel");
		}
	}
}

handler_result ssh_test_client::handle_kex_done(kex const& k) {
	auto key = k.server_host_key();
	logger_.log(logger::info, "Server host key ({}) fingerprint: {}", to_string(key.type()), key.fingerprint(crypto(), call_context()));
	//check the above key is trusted, if not set_error_and_disconnect(ssh_key_exchange_failed);
	return ssh_client::handle_kex_done(k);
}

bool ssh_test_client::on_version(std::uint32_t version, sftp::ext_data_view data) {
	// we have sftp connection, start interactive mode
	handler_.emit<events::command_prompt>();
	return true;
}

void ssh_test_client::on_failure(sftp::call_handle, sftp::sftp_error err) {
	logger_.log(logger::debug_trace, "command on_failure");
	success_cb_ = nullptr;
	if(fail_cb_) {
		logger_.log(logger::debug_trace, "fail cb set");
		fail_cb_();
		fail_cb_ = nullptr;
	} else {
		std::osyncstream out(std::cout);
		out << "Failure = " << err.code() << ", " << err.message() << std::endl;
		handler_.emit<events::command_prompt>();
	}
}

void ssh_test_client::on_open_file(sftp::call_handle id, sftp::open_file_data result) {

}

void ssh_test_client::on_read_file(sftp::call_handle id, sftp::read_file_data result) {

}

void ssh_test_client::on_write_file(sftp::call_handle id, sftp::write_file_data result) {

}

void ssh_test_client::on_close_file(sftp::call_handle id, sftp::close_file_data result) {

}

void ssh_test_client::on_stat_file(sftp::call_handle, sftp::state_file_data result) {

}

void ssh_test_client::on_setstat_file(sftp::call_handle, sftp::setstate_file_data result) {

}

void ssh_test_client::on_open_dir(sftp::call_handle id, sftp::open_dir_data result) {
	fail_cb_ = [&, handle = result.handle]
		{
			logger_.log(logger::debug_trace, "close dir1");

			auto s = sftp();
			if(s) {
				logger_.log(logger::debug_trace, "close dir");
				s->close_dir(handle);
			}
		};

	success_cb_ = [&, handle = result.handle]
		{
			auto s = sftp();
			if(s) {
				s->read_dir(handle);
			}
		};

	success_cb_();
}

void ssh_test_client::on_read_dir(sftp::call_handle id, sftp::read_dir_data result) {
	logger_.log(logger::debug_trace, "on read dir");

	// lets try to read more
	if(success_cb_) {
		success_cb_();
	}

	std::osyncstream out(std::cout);
	for(auto&& v : result.files) {
		out << v.longname << "\n";
	}
	out << std::flush;
}

void ssh_test_client::on_close_dir(sftp::call_handle id, sftp::close_dir_data result) {
	logger_.log(logger::debug_trace, "on close dir");
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_remove_file(sftp::call_handle, sftp::remove_file_data result) {

}

void ssh_test_client::on_rename(sftp::call_handle, sftp::rename_data result) {

}

void ssh_test_client::on_mkdir(sftp::call_handle, sftp::mkdir_data result) {

}

void ssh_test_client::on_remove_dir(sftp::call_handle, sftp::remove_dir_data result) {

}

void ssh_test_client::on_stat(sftp::call_handle, sftp::stat_data result) {

}

void ssh_test_client::on_setstat(sftp::call_handle, sftp::setstat_data result) {

}

void ssh_test_client::on_readlink(sftp::call_handle, sftp::readlink_data result) {

}

void ssh_test_client::on_symlink(sftp::call_handle, sftp::symlink_data result) {

}

void ssh_test_client::on_realpath(sftp::call_handle, sftp::realpath_data result) {

}

void ssh_test_client::on_extended(sftp::call_handle, sftp::extended_data result) {

}

}
