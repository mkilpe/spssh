
#include "client.hpp"
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

namespace securepath::ssh {

test_client_commands::test_client_commands()
: test_client_config(client_config{test_tool_default_config()})
, command_parser(false)
{
	add(help, "help", "", "show help");
	add(host, "host", "h", "host to connect");
	add(port, "port", "p", "port to connect");
	add(username, "user", "u", "username to connect");
	add(password, "password", "", "password");
	add(config_file, "config", "c", "config file");
	add(service, "service", "", "ssh service to autheticate for");
	add(subsystem, "subsystem", "sub", "subsystem to start");

	config.add_commands(*this);
}

void test_client_commands::create_config(logger& log) {
	side = transport_side::client;
	my_version.software = "spssh_test_client";

	config.parse(log, *this);
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
	, client_(handler, config, log_, out_buf_, ccontext)
	{
		timer_.expires_at(std::chrono::steady_clock::time_point::max());
	}

	asio::awaitable<void> connect(tcp::endpoint ep) {
		log_.log(logger::info, "Connecting to {}", ep);

		auto [e] = co_await socket_.async_connect(ep, asio::experimental::as_tuple(asio::use_awaitable));
		if(!e) {
			start();
		} else {
			log_.log(logger::error, "Connect failed: {}", e.message());
			io_context_.stop();
		}
	}

	void start() {
		log_.log(logger::info, "Connected");

		asio::co_spawn(socket_.get_executor(),
			[self = shared_from_this()]{ return self->reader(); }, asio::detached);

		asio::co_spawn(socket_.get_executor(),
			[self = shared_from_this()]{ return self->writer(); }, asio::detached);

	}

private:
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
			for (; socket_.is_open();) {
				std::size_t n = co_await socket_.async_read_some(
					asio::buffer(read_data.data(), read_data.size()), asio::use_awaitable);

				in_buf_.add(read_data.substr(0, n));
				client_process();
			}
		} catch (std::exception&) {
			stop();
		}
	}

	asio::awaitable<void> writer() {
		try {
			while (socket_.is_open()) {
				if (out_buf_.empty()) {
					asio::error_code ec;
					co_await timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
				} else {
					std::string buf = out_buf_.extract_committed();
					log_.log(logger::debug, "writing out: {}", to_span(buf));
					co_await asio::async_write(socket_, asio::buffer(buf), asio::use_awaitable);
				}
			}
		} catch (std::exception&) {
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

	string_in_buffer in_buf_;
	string_out_buffer out_buf_;

	ssh_test_client client_;
};

namespace events {
	struct input {
		typedef void type();
	};
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
	}

	~impl() {
		stop_handler();
		if(thread_.joinable()) {
			thread_.join();
		}
	}

	bool start() {
		auto result = tcp::resolver(io_context_).resolve(config_.host, "ssh");
		if(result.begin() == result.end()) {
			std::cerr << "Failed to resolve address\n";
			return false;
		}

		auto endpoint = result.begin()->endpoint();
		endpoint.port(config_.port);

		auto client = std::make_shared<ssh_client_session>(*this, io_context_, log_, config_.config.get_crypto_context(), config_);
		asio::co_spawn(io_context_, client->connect(endpoint), asio::detached);

		thread_ = std::thread{
			[&]{
				io_context_.run();
				main_loop_.stop();
			}};

		main_loop_.thread_entry();

		return true;
	}

	void handle_event(std::unique_ptr<event_base> ev) {
		dispatch(*ev
			, event_dest<events::input>(&impl::get_input));
	}

	void get_input() {

	}

	single_thread_event_loop& main_loop_;
	asio::io_context io_context_;
	logger& log_;
	asio::signal_set signals_;
	test_client_commands config_;
	std::thread thread_;
};

test_client::test_client(test_client_commands const& c)
: main_loop_(log_)
, impl_(std::make_unique<impl>(c, log_, main_loop_))
{
}

test_client::~test_client()
{
}

int test_client::run() {
	impl_->start();
	return 0;
}

}
