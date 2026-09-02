#ifndef SP_SSH_TEST_SFTP_FIXTURES_HEADER
#define SP_SSH_TEST_SFTP_FIXTURES_HEADER

#include "test/random.hpp"
#include "ssh/core/transport_base.hpp"
#include "ssh/core/connection/channel.hpp"
#include "ssh/services/sftp/sftp_client.hpp"
#include "ssh/services/sftp/sftp_server.hpp"

#include <memory>
#include <string>
#include <vector>

namespace securepath::ssh::test {

/// transport_base implementation that captures sent ssh packet payloads, no crypto involved
class sftp_record_transport : public transport_base {
public:
	sftp_record_transport(logger& l)
	: log_(l)
	{
	}

	ssh_error_code error() const override { return error_; }
	std::string error_message() const override { return error_msg_; }
	void set_error(ssh_error_code code, std::string_view message = {}) override {
		error_ = code;
		error_msg_ = message;
	}
	void set_error_and_disconnect(ssh_error_code code, std::string_view message = {}) override {
		set_error(code, message);
		disconnected_ = true;
	}
	ssh_config const& config() const override { return config_; }
	crypto_context const& crypto() const override { return ccontext_; }
	crypto_call_context call_context() const override { return crypto_call_context{log_, test_rand}; }
	std::optional<out_packet_record> alloc_out_packet(std::size_t data_size) override;
	bool write_alloced_out_packet(out_packet_record const&) override;
	const_span session_id() const override { return {}; }
	std::uint32_t max_in_packet_size() override { return 32768; }
	std::uint32_t max_out_packet_size() override { return 32768; }

	bool disconnected() const { return disconnected_; }

public:
	/// captured ssh packet payloads, first byte of each is the ssh packet type
	std::vector<byte_vector> sent;

private:
	logger& log_;
	ssh_config config_{};
	crypto_context ccontext_{};
	byte_vector buf_;
	ssh_error_code error_{};
	std::string error_msg_;
	bool disconnected_{};
};

/// single parsed sftp packet, payload is the data after the length and type tag
struct sftp_packet_data {
	sftp::sftp_packet_type type{};
	byte_vector payload;
};

/// concatenate the data of all captured channel_data packets to single sftp stream
byte_vector channel_data_stream(std::vector<byte_vector> const& sent);

/// parse the given sftp stream into individual packets
std::vector<sftp_packet_data> parse_sftp_packets(const_span stream);

/// sftp client callback that records everything for inspection
class recording_client_callback : public sftp::sftp_client_callback {
public:
	struct event {
		std::string name;
		sftp::call_handle handle{};
	};

	bool on_version(std::uint32_t version, std::vector<sftp::ext_data_view> const& ext) override;
	void on_failure(sftp::call_handle, sftp::sftp_error) override;
	void on_open_file(sftp::call_handle, sftp::open_file_data) override;
	void on_read_file(sftp::call_handle, sftp::read_file_data) override;
	void on_write_file(sftp::call_handle, sftp::write_file_data) override;
	void on_close_file(sftp::call_handle, sftp::close_file_data) override;
	void on_stat_file(sftp::call_handle, sftp::state_file_data) override;
	void on_setstat_file(sftp::call_handle, sftp::setstate_file_data) override;
	void on_open_dir(sftp::call_handle, sftp::open_dir_data) override;
	void on_read_dir(sftp::call_handle, sftp::read_dir_data) override;
	void on_close_dir(sftp::call_handle, sftp::close_dir_data) override;
	void on_remove_file(sftp::call_handle, sftp::remove_file_data) override;
	void on_rename(sftp::call_handle, sftp::rename_data) override;
	void on_mkdir(sftp::call_handle, sftp::mkdir_data) override;
	void on_remove_dir(sftp::call_handle, sftp::remove_dir_data) override;
	void on_stat(sftp::call_handle, sftp::stat_data) override;
	void on_setstat(sftp::call_handle, sftp::setstat_data) override;
	void on_readlink(sftp::call_handle, sftp::readlink_data) override;
	void on_symlink(sftp::call_handle, sftp::symlink_data) override;
	void on_realpath(sftp::call_handle, sftp::realpath_data) override;
	void on_extended(sftp::call_handle, sftp::extended_data) override;

	std::string last_event() const { return events.empty() ? std::string() : events.back().name; }
	sftp::call_handle last_handle() const { return events.empty() ? 0 : events.back().handle; }

public:
	bool accept_version{true};
	std::uint32_t version{};
	std::vector<sftp::ext_data> extensions;
	std::vector<event> events;
	sftp::sftp_error last_error;
	sftp::file_handle last_file;
	sftp::dir_handle last_dir;
	byte_vector last_data;
	sftp::file_attributes last_attrs;
	std::vector<sftp::file_info> last_files;
	std::string last_path;
};

/// sftp server backend that records everything for inspection
class recording_server_backend : public sftp::sftp_server_backend {
public:
	struct event {
		std::string name;
		sftp::call_context ctx{};
	};

	using sftp::sftp_server_backend::sftp_server_backend;

	void on_init(std::uint32_t version, std::vector<sftp::ext_data_view> const& data) override;
	void on_open_file(sftp::call_context, std::string_view path, sftp::open_mode mode, sftp::file_attributes attrs) override;
	void on_close_file(sftp::call_context, sftp::file_handle_view) override;
	void on_read_file(sftp::call_context, sftp::file_handle_view, std::uint64_t pos, std::uint32_t size) override;
	void on_write_file(sftp::call_context, sftp::file_handle_view, std::uint64_t pos, const_span data) override;
	void on_stat_file(sftp::call_context, sftp::file_handle_view) override;
	void on_setstat_file(sftp::call_context, sftp::file_handle_view, sftp::file_attributes) override;
	void on_open_dir(sftp::call_context, std::string_view path) override;
	void on_read_dir(sftp::call_context, sftp::dir_handle_view) override;
	void on_close_dir(sftp::call_context, sftp::dir_handle_view) override;
	void on_remove_file(sftp::call_context, std::string_view path) override;
	void on_rename(sftp::call_context, std::string_view old_path, std::string_view new_path) override;
	void on_mkdir(sftp::call_context, std::string_view path, sftp::file_attributes) override;
	void on_remove_dir(sftp::call_context, std::string_view path) override;
	void on_stat(sftp::call_context, std::string_view path, bool follow_symlinks) override;
	void on_setstat(sftp::call_context, std::string_view path, sftp::file_attributes) override;
	void on_readlink(sftp::call_context, std::string_view path) override;
	void on_symlink(sftp::call_context, std::string_view link, std::string_view path) override;
	void on_realpath(sftp::call_context, std::string_view path) override;
	void on_extended(sftp::call_context, std::string_view ext_request, const_span data) override;

	std::string last_event() const { return events.empty() ? std::string() : events.back().name; }
	sftp::call_context last_ctx() const { return events.empty() ? 0 : events.back().ctx; }
	sftp::sftp_server_interface* iface() const { return s_; }

public:
	/// if set, respond to init with the default version negotiation
	bool auto_version{true};
	std::uint32_t init_version{};
	std::vector<sftp::ext_data> extensions;
	std::vector<event> events;
	std::string last_path;
	std::string last_target;
	std::string last_handle;
	sftp::open_mode last_mode{};
	sftp::file_attributes last_attrs;
	std::uint64_t last_pos{};
	std::uint32_t last_size{};
	byte_vector last_data;
	bool last_follow{};
	std::string last_ext_request;
};

/// widen access for feeding packets directly
struct exposed_sftp_client : sftp::sftp_client {
	using sftp::sftp_client::sftp_client;
	using sftp::sftp_client::handle_sftp_packet;

	std::size_t pending_calls() const { return remote_calls_.size(); }
};

/// widen access for feeding packets directly
struct exposed_sftp_server : sftp::sftp_server {
	using sftp::sftp_server::sftp_server;
	using sftp::sftp_server::handle_sftp_packet;
};

/// construct a channel in established state, ready to be upgraded to sftp_server
channel make_established_channel(transport_base&,
	std::uint32_t remote_window = 2*1024*1024, std::uint32_t remote_max_packet = 32768);

}

#endif
