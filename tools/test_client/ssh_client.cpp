
#include "events.hpp"
#include "ssh_client.hpp"
#include "ssh/core/connection/ssh_connection.hpp"
#include "ssh/core/kex.hpp"
#include "ssh/services/sftp/sftp.hpp"
#include "ssh/services/sftp/sftp_client.hpp"
#include "ssh/core/ssh_public_key.hpp"
#include "ssh/client/auth_service.hpp"
#include "ssh/common/util.hpp"
#include "tools/common/util.hpp"

#include <fstream>
#include <iostream>
#include <sstream>
#include <syncstream>

namespace securepath::ssh {

namespace {

// answers keyboard-interactive prompts from the terminal, reusing a known password for hidden prompts
class tool_client_auth : public default_client_auth {
public:
	tool_client_auth(transport_base& transport, client_config const& config)
	: default_client_auth(transport, config)
	, config_(config)
	{}

protected:
	bool supports_interactive() const override { return true; }

	interactive_result on_interactive(interactive_request const& req, std::vector<std::string>& results) override {
		std::osyncstream out(std::cout);
		if(!req.name.empty()) {
			out << req.name << '\n';
		}
		if(!req.instruction.empty()) {
			out << req.instruction << '\n';
		}
		out.emit();
		for(auto const& p : req.prompts) {
			// a hidden prompt is a password prompt, answer with a known password to avoid asking twice
			if(!p.echo && !config_.password.empty()) {
				results.push_back(config_.password);
			} else {
				results.push_back(prompt_input(std::string(p.text), p.echo));
			}
		}
		return interactive_result::data;
	}

private:
	client_config const& config_;
};

enum class host_key_check { trusted, added, changed, unwritable };

// simple known hosts file, one "host keytype base64key" line per host; trust on first use appends
host_key_check check_known_hosts(std::string const& path, std::string const& host, ssh_public_key const& key) {
	std::string const algo(to_string(key.type()));
	auto blob = to_byte_vector(key);
	std::string const b64 = encode_base64(blob);

	std::ifstream in(path);
	std::string line;
	while(std::getline(in, line)) {
		std::istringstream ls(line);
		std::string h, a, k;
		if(ls >> h >> a >> k && h == host) {
			return (a == algo && k == b64) ? host_key_check::trusted : host_key_check::changed;
		}
	}
	in.close();

	std::ofstream out(path, std::ios::app);
	if(!out) {
		return host_key_check::unwritable;
	}
	out << host << ' ' << algo << ' ' << b64 << '\n';
	return host_key_check::added;
}

}

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
					std::shared_ptr<sftp::sftp_client_callback> self{this, [](void*){}};
					// the transfer handler runs get/put and forwards everything else to this
					transfers_ = std::make_shared<sftp::sftp_transfer_handler>(self);
					return std::make_unique<sftp::sftp_client>(transfers_, t, sinfo,
						default_buffer_size, test_config_.subsystem);
				});

		if(ch) {
			channel_id_ = ch->id();
			logger_.log(logger::debug_trace, "channel id is {}", channel_id_);
		} else {
			logger_.log(logger::error, "failed to open channel");
		}
	}
}

std::unique_ptr<auth_service> ssh_test_client::construct_auth() {
	return std::make_unique<tool_client_auth>(*this, config_);
}

handler_result ssh_test_client::handle_kex_done(kex const& k) {
	auto key = k.server_host_key();
	auto fingerprint = key.fingerprint(crypto(), call_context());
	logger_.log(logger::info, "Server host key ({}) fingerprint: {}", to_string(key.type()), fingerprint);

	if(!test_config_.known_hosts.empty()) {
		auto const& host = test_config_.host_label;
		switch(check_known_hosts(test_config_.known_hosts, host, key)) {
			case host_key_check::changed:
				logger_.log(logger::error, "host key for {} changed, refusing to connect [{}]", host, fingerprint);
				std::osyncstream(std::cout) << "Host key verification failed for " << host << ", key is " << fingerprint << std::endl;
				set_error_and_disconnect(ssh_key_exchange_failed, "host key verification failed");
				return handler_result::handled;
			case host_key_check::added:
				std::osyncstream(std::cout) << "Trusting new host " << host << " with key " << fingerprint << std::endl;
				break;
			case host_key_check::unwritable:
				logger_.log(logger::error, "cannot write known hosts file {}", test_config_.known_hosts);
				break;
			case host_key_check::trusted:
				logger_.log(logger::info, "host key for {} is trusted", host);
				break;
		}
	}
	return ssh_client::handle_kex_done(k);
}

bool ssh_test_client::on_version(std::uint32_t version, std::vector<sftp::ext_data_view> const& extensions) {
	// we have sftp connection, start interactive mode
	handler_.emit<events::command_prompt>();
	return true;
}

void ssh_test_client::on_failure(sftp::call_handle, sftp::sftp_error err) {
	logger_.log(logger::debug_trace, "command on_failure");
	note_failure();
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

void ssh_test_client::on_open_file(sftp::call_handle, sftp::open_file_data result) {
	logger_.log(logger::debug_trace, "on_open_file");
	std::osyncstream(std::cout) << "opened file, handle of " << result.handle.size() << " bytes" << std::endl;
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_read_file(sftp::call_handle, sftp::read_file_data result) {
	logger_.log(logger::debug_trace, "on_read_file");
	std::osyncstream out(std::cout);
	if(result.data.empty()) {
		out << "read: end of file" << std::endl;
	} else {
		out << "read " << result.data.size() << " bytes" << std::endl;
	}
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_write_file(sftp::call_handle, sftp::write_file_data result) {
	logger_.log(logger::debug_trace, "on_write_file");
	std::osyncstream(std::cout) << "wrote" << std::endl;
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_close_file(sftp::call_handle, sftp::close_file_data result) {
	logger_.log(logger::debug_trace, "on_close_file");
	std::osyncstream(std::cout) << "closed file" << std::endl;
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_stat_file(sftp::call_handle, sftp::stat_file_data result) {
	logger_.log(logger::debug_trace, "on_stat_file");
	std::osyncstream out(std::cout);
	out << "fstat = " << to_string(result.attrs) << std::endl;
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_setstat_file(sftp::call_handle, sftp::setstat_file_data result) {
	logger_.log(logger::debug_trace, "on_setstat_file");
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_open_dir(sftp::call_handle id, sftp::open_dir_data result) {
	fail_cb_ = [&, handle = result.handle]
		{
			auto s = sftp();
			if(s) {
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
	logger_.log(logger::debug_trace, "on_read_dir");

	if(result.files.empty()) {
		// end of the listing, close the directory
		success_cb_ = nullptr;
		if(fail_cb_) {
			fail_cb_();
			fail_cb_ = nullptr;
		}
	} else {
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
}

void ssh_test_client::on_close_dir(sftp::call_handle id, sftp::close_dir_data result) {
	logger_.log(logger::debug_trace, "on_close_dir");
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_remove_file(sftp::call_handle, sftp::remove_file_data result) {
	logger_.log(logger::debug_trace, "on_remove_file");
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_rename(sftp::call_handle, sftp::rename_data result) {
	logger_.log(logger::debug_trace, "on_rename");
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_mkdir(sftp::call_handle, sftp::mkdir_data result) {
	logger_.log(logger::debug_trace, "on_mkdir");
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_remove_dir(sftp::call_handle, sftp::remove_dir_data result) {
	logger_.log(logger::debug_trace, "on_remove_dir");
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_stat(sftp::call_handle, sftp::stat_data result) {
	logger_.log(logger::debug_trace, "on_stat");
	std::osyncstream out(std::cout);
	out << "stat = " << to_string(result.attrs) << std::endl;
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_setstat(sftp::call_handle, sftp::setstat_data result) {
	logger_.log(logger::debug_trace, "on_setstat");
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_readlink(sftp::call_handle, sftp::readlink_data result) {
	logger_.log(logger::debug_trace, "on_readlink");
	std::osyncstream out(std::cout);
	out << "link = " << result.path << std::endl;
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_symlink(sftp::call_handle, sftp::symlink_data result) {
	logger_.log(logger::debug_trace, "on_symlink");
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_realpath(sftp::call_handle, sftp::realpath_data result) {
	logger_.log(logger::debug_trace, "on_realpath");
	std::osyncstream out(std::cout);
	out << "path = " << result.path << std::endl;
	handler_.emit<events::command_prompt>();
}

void ssh_test_client::on_extended(sftp::call_handle, sftp::extended_data result) {
	logger_.log(logger::debug_trace, "on_extended");
	handler_.emit<events::command_prompt>();
}

}
