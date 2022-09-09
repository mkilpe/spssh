
#include "ssh_client.hpp"
#include "ssh/core/connection/ssh_connection.hpp"
#include "ssh/core/kex.hpp"
#include "ssh/services/sftp/sftp.hpp"
#include "ssh/services/sftp/sftp_client.hpp"

namespace securepath::ssh {

ssh_test_client::ssh_test_client(event_handler& handler, test_client_config const& conf, logger& log, out_buffer& buf, crypto_context c)
: ssh_client(conf, log, buf, c)
, handler_(handler)
, test_config_(conf)
{
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
			logger_.log(logger::debug_trace, "channel id is {}", ch->id());
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
	return true;
}

void ssh_test_client::on_open_file(sftp_result<sftp::open_file_data> result) {

}

void ssh_test_client::on_read_file(sftp_result<sftp::read_file_data> result) {

}

void ssh_test_client::on_write_file(sftp_result<sftp::write_file_data> result) {

}

void ssh_test_client::on_close_file(sftp_result<sftp::close_file_data> result) {

}

void ssh_test_client::on_open_dir(sftp_result<sftp::open_file_data> result) {

}

void ssh_test_client::on_read_dir(sftp_result<sftp::read_dir_data> result) {

}

void ssh_test_client::on_close_dir(sftp_result<sftp::close_dir_data> result) {

}

}
