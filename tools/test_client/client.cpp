
#include "client.hpp"
#include "events.hpp"
#include "ssh_client.hpp"
#include "ssh/common/string_buffers.hpp"
#include "tools/common/config_parser.hpp"
#include "tools/common/event_handler.hpp"
#include "tools/common/util.hpp"

#include <coroutine>
#include <asio.hpp>
#include <asio/experimental/as_tuple.hpp>

#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <stdexcept>
#include <syncstream>
#include <functional>
#include <optional>

namespace securepath::ssh {

test_client_commands::test_client_commands()
: test_client_config(client_config{test_tool_default_config()})
, command_parser(false)
{
	add(help, "help", "", "show help");
	add(verbose, "verbose", "v", "verbose logging");
	add(very_verbose, "very-verbose", "vv", "very verbose logging");
	add(host, "host", "h", "host to connect");
	add(port, "port", "p", "port to connect");
	add(username, "user", "u", "username to connect");
	add(password, "password", "", "password");
	add(config_file, "config", "c", "config file");
	add(service, "service", "", "ssh service to autheticate for");
	add(channel, "channel", "", "channel type to open");
	add(subsystem, "subsystem", "sub", "subsystem to request on the channel");
	add(known_hosts, "known-hosts", "", "file of trusted host keys, checked and updated on connect");

	config.add_commands(*this);
}

void test_client_commands::create_config(logger& log) {
	side = transport_side::client;
	my_version.software = "spssh_test_client";
	// openssh style label, plain host for the default port, [host]:port otherwise
	host_label = port == 22 ? host : "[" + host + "]:" + std::to_string(port);

	config.parse(log, *this);

	// with no key and no password there is nothing to authenticate with, so ask for a password up front;
	// keyboard-interactive prompts are answered live during authentication
	if(password.empty() && private_keys.empty()) {
		password = prompt_input("Password: ", false);
	}
}

using tcp = asio::ip::tcp;
using namespace std::literals;

class ssh_client_session : public std::enable_shared_from_this<ssh_client_session>
{
public:
	ssh_client_session(event_handler& handler, asio::io_context& io_context, logger& log, crypto_context ccontext, test_client_config const& config)
	: io_context_(io_context)
	, socket_(io_context_)
	, timer_(io_context_)
	, log_(log)
	, handler_(handler)
	, client_(handler, config, log_, out_buf_, ccontext)
	{
		timer_.expires_at(std::chrono::steady_clock::time_point::max());
	}

	asio::awaitable<void> connect(tcp::endpoint ep) {
		log_.log(logger::info, "Connecting to {}", ep);

		auto [e] = co_await socket_.async_connect(ep, asio::experimental::as_tuple(asio::use_awaitable));
		if(!e) {
			connected_ = true;
			start();
		} else {
			log_.log(logger::error, "Connect failed: {}", e.message());
			io_context_.stop();
		}
	}

	// a non-zero process exit code: connect never succeeded, or the session ended in error
	bool failed() const {
		return !connected_ || client_.failed();
	}

	void start() {
		log_.log(logger::info, "Connected");

		asio::co_spawn(socket_.get_executor(),
			[self = shared_from_this()]{ return self->reader(); }, asio::detached);

		asio::co_spawn(socket_.get_executor(),
			[self = shared_from_this()]{ return self->writer(); }, asio::detached);

	}

	void list_files(std::string path) {
		post_command([=](auto& sftp)
			{
				sftp.open_dir(path);
			});
	}

	void realpath(std::string path) {
		post_command([=](auto& sftp)
			{
				sftp.realpath(path);
			});
	}

	void stat(std::string path) {
		post_command([=](auto& sftp)
			{
				sftp.stat(path);
			});
	}

	void download(std::string remote, std::string local) {
		post_transfer([this, remote, local](auto& h, auto& sftp)
			{
				return h.download(sftp, remote, std::make_unique<sftp::file_output>(local), {}, transfer_done("download"), progress("download", {}));
			});
	}

	void upload(std::string local, std::string remote) {
		auto input = std::make_unique<sftp::file_input>(local);
		if(!input->is_open()) {
			std::osyncstream(std::cout) << "cannot open " << local << std::endl;
			handler_.emit<events::command_prompt>();
			return;
		}
		post_transfer([this, in = std::shared_ptr<sftp::file_input>(std::move(input)), remote](auto& h, auto& sftp)
			{
				return h.upload(sftp, remote, std::make_unique<owned_input>(in), {}, transfer_done("upload"), progress("upload", in->size()));
			});
	}

	ssh_test_client& ssh_client() {
		return client_;
	}

private:
	void post_command(std::function<void(sftp::sftp_client&)> func) {
		// make sure we have mutually exclusive execution with the network handling
		asio::post(socket_.get_executor(), [this, func = std::move(func)]
			{
				auto sftp = client_.sftp();
				if(sftp) {
					func(*sftp);
					// release the write wait to make sure the buffer gets flushed
					timer_.cancel_one();
				}
			});
	}

	// a transfer_input that keeps its file_input alive
	struct owned_input : sftp::transfer_input {
		std::shared_ptr<sftp::file_input> in;
		explicit owned_input(std::shared_ptr<sftp::file_input> i) : in(std::move(i)) {}
		std::optional<std::uint64_t> size() const override { return in->size(); }
		std::size_t read(std::uint64_t offset, span out) override { return in->read(offset, out); }
	};

	sftp::transfer_done transfer_done(std::string what) {
		return [this, what](sftp::transfer_id, sftp::transfer_result const& r) {
			std::osyncstream out(std::cout);
			// a newline first to leave the in place progress line
			out << '\n';
			if(r.error) {
				client_.note_failure();
				out << what << " failed: " << r.error.message() << std::endl;
			} else if(r.cancelled) {
				out << what << " cancelled after " << r.bytes << " bytes" << std::endl;
			} else {
				out << what << " done, " << r.bytes << " bytes" << std::endl;
			}
			handler_.emit<events::command_prompt>();
		};
	}

	sftp::transfer_progress progress(std::string what, std::optional<std::uint64_t> total) {
		return [what, total, last = std::uint64_t{0}](sftp::transfer_id, std::uint64_t bytes) mutable {
			// throttle so a fast transfer does not flood the terminal; the final count comes from transfer_done
			if(bytes < last + 64*1024) {
				return;
			}
			last = bytes;
			std::osyncstream out(std::cout);
			if(total && *total) {
				out << '\r' << what << ' ' << (bytes * 100 / *total) << "% (" << bytes << '/' << *total << ")" << std::flush;
			} else {
				out << '\r' << what << ' ' << bytes << " bytes" << std::flush;
			}
		};
	}

	void post_transfer(std::function<sftp::transfer_id(sftp::sftp_transfer_handler&, sftp::sftp_client_interface&)> func) {
		asio::post(socket_.get_executor(), [this, func = std::move(func)]
			{
				auto sftp = client_.sftp();
				auto* h = client_.transfers();
				if(sftp && h) {
					if(func(*h, *sftp) == 0) {
						std::osyncstream(std::cout) << "could not start transfer" << std::endl;
						handler_.emit<events::command_prompt>();
					}
					timer_.cancel_one();
				}
			});
	}

	void client_process() {
		transport_op res;
		std::size_t bsize;
		do {
			bsize = in_buf_.size();
			res = client_.process(in_buf_);
		} while(res != transport_op::disconnected && bsize != in_buf_.size());

		if(res == transport_op::disconnected) {
			stop();
		} else if(!out_buf_.empty()) {
			timer_.cancel_one();
		}
	}

	asio::awaitable<void> reader() {
		try {
			client_process();

			std::string read_data;
			read_data.resize(1024);
			while(socket_.is_open()) {
				std::size_t n = co_await socket_.async_read_some(
					asio::buffer(read_data.data(), read_data.size()), asio::use_awaitable);

				in_buf_.add(read_data.substr(0, n));
				client_process();
			}
		} catch(std::exception&) {
			stop();
		}
	}

	asio::awaitable<void> writer() {
		try {
			while(socket_.is_open()) {
				if(out_buf_.empty()) {
					asio::error_code ec;
					co_await timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
				} else {
					std::string buf = out_buf_.extract_committed();
					log_.log(logger::debug_trace, "writing out: {}", to_span(buf));
					co_await asio::async_write(socket_, asio::buffer(buf), asio::use_awaitable);
				}
			}
		} catch(std::exception&) {
			stop();
		}
	}

	void stop() {
		log_.log(logger::info, "Closing connection");
		socket_.close();
		timer_.cancel();

		io_context_.stop();
	}

private:
	asio::io_context& io_context_;
	tcp::socket socket_;
	asio::steady_timer timer_;

	logger& log_;
	event_handler& handler_;

	string_in_buffer in_buf_;
	string_out_buffer out_buf_;

	ssh_test_client client_;
	bool connected_{};
};

static void ensure_args(auto const& args, std::size_t amount) {
	if(args.size() != amount) {
		throw std::runtime_error("wrong amount of arguments");
	}
}

struct test_client::impl : public event_handler {
	impl(test_client_commands const& c, logger& log, single_thread_event_loop& loop)
	: event_handler(loop)
	, main_loop_(loop)
	, log_(log)
	, signals_(io_context_, SIGINT, SIGTERM)
	, config_(c)
	{
		config_.create_config(log_);

		signals_.async_wait(
			[&](auto, auto){
				io_context_.stop();
			});

		commands_["ls"] = [&](auto args)
			{
				session_->list_files(args.empty() ? "" : args[0]);
				return true;
			};

		commands_["realpath"] = [&](auto args)
			{
				ensure_args(args, 1);
				session_->realpath(args[0]);
				return true;
			};

		commands_["stat"] = [&](auto args)
			{
				ensure_args(args, 1);
				session_->stat(args[0]);
				return true;
			};

		commands_["get"] = [&](auto args)
			{
				ensure_args(args, 2);
				session_->download(args[0], args[1]);
				return true;
			};

		commands_["put"] = [&](auto args)
			{
				ensure_args(args, 2);
				session_->upload(args[0], args[1]);
				return true;
			};

		commands_["exit"] = [&](auto)
			{
				io_context_.stop();
				return true;
			};
	}

	~impl() {
		stop_handler();
		if(thread_.joinable()) {
			thread_.join();
		}
	}

	int run() {
		auto result = tcp::resolver(io_context_).resolve(config_.host, "ssh");
		if(result.begin() == result.end()) {
			std::cerr << "Failed to resolve address\n";
			return 1;
		}

		auto endpoint = result.begin()->endpoint();
		endpoint.port(config_.port);

		session_ = std::make_shared<ssh_client_session>(*this, io_context_, log_, config_.config.get_crypto_context(), config_);
		asio::co_spawn(io_context_, session_->connect(endpoint), asio::detached);

		thread_ = std::thread{
			[&]{
				io_context_.run();
				main_loop_.stop();
			}};

		main_loop_.thread_entry();

		return session_->failed() ? 1 : 0;
	}

	void handle_event(std::unique_ptr<event_base> ev) {
		dispatch(*ev
			, event_dest<events::command_prompt>(&impl::get_input));
	}

	void get_input() {
		bool in_progress = false;
		std::string line;
		{
			std::osyncstream out(std::cout);
			out << "?> " << std::flush;
		}
		if(std::getline(std::cin, line)) {
			in_progress = handle_command_line(line);
		}
		if(!in_progress) {
			this->emit<events::command_prompt>();
		}
	}

	bool handle_command_line(std::string const& line) {
		bool res = false;
		try {
			std::vector<std::string> arguments;
			std::string cmd = tokenise_command(line, arguments);
			if(!cmd.empty()) {
				auto it = commands_.find(cmd);
				if(it != commands_.end()) {
					res = it->second(std::move(arguments));
				} else {
					std::osyncstream out(std::cout);
					out << "Unknown command" << std::endl;
				}
			}
		} catch(std::exception const& e) {
			std::osyncstream out(std::cout);
			out << e.what() << std::endl;
		}
		return res;
	}

private:
	single_thread_event_loop& main_loop_;
	asio::io_context io_context_;
	logger& log_;
	asio::signal_set signals_;
	test_client_commands config_;
	std::map<std::string, std::function<bool(std::vector<std::string>)>> commands_;
	std::thread thread_;
	std::shared_ptr<ssh_client_session> session_;
};

static logger::type make_log_level(test_client_commands const& c) {
	if(c.very_verbose) {
		return logger::log_all;
	}
	if(c.verbose) {
		return logger::type(logger::error | logger::info | logger::debug);
	}
	return logger::error;
}

test_client::test_client(test_client_commands const& c)
: log_(make_log_level(c))
, main_loop_(log_)
, impl_(std::make_unique<impl>(c, log_, main_loop_))
{
}

test_client::~test_client()
{
}

int test_client::run() {
	return impl_->run();
}

}
