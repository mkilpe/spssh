#ifndef SP_SSH_TOOLS_TEST_CLIENT_SSH_CLIENT_HEADER
#define SP_SSH_TOOLS_TEST_CLIENT_SSH_CLIENT_HEADER

#include "client_config.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/services/sftp/sftp_client.hpp"
#include "ssh/services/sftp/sftp_client_interface.hpp"
#include "tools/common/event_handler.hpp"

namespace securepath::ssh {

class ssh_test_client : public ssh_client, public sftp::sftp_client_callback {
public:
	ssh_test_client(event_handler& handler, test_client_config const&, logger& log, out_buffer&, crypto_context = default_crypto_context());

	sftp::sftp_client* sftp();

protected:
	handler_result handle_kex_done(kex const&) override;

	void on_service_started() override;

protected:
	bool on_version(std::uint32_t version, sftp::ext_data_view data) override;
	void on_failure(sftp::call_handle, sftp::sftp_error err) override;
	void on_open_file(sftp::call_handle, sftp::open_file_data result) override;
	void on_read_file(sftp::call_handle, sftp::read_file_data result) override;
	void on_write_file(sftp::call_handle, sftp::write_file_data result) override;
	void on_close_file(sftp::call_handle, sftp::close_file_data result) override;
	void on_stat_file(sftp::call_handle, sftp::state_file_data result) override;
	void on_setstat_file(sftp::call_handle, sftp::setstate_file_data result) override;
	void on_open_dir(sftp::call_handle, sftp::open_dir_data result) override;
	void on_read_dir(sftp::call_handle, sftp::read_dir_data result) override;
	void on_close_dir(sftp::call_handle, sftp::close_dir_data result) override;
	void on_remove_file(sftp::call_handle, sftp::remove_file_data result) override;
	void on_rename(sftp::call_handle, sftp::rename_data result) override;
	void on_mkdir(sftp::call_handle, sftp::mkdir_data result) override;
	void on_remove_dir(sftp::call_handle, sftp::remove_dir_data result) override;
	void on_stat(sftp::call_handle, sftp::stat_data result) override;
	void on_setstat(sftp::call_handle, sftp::setstat_data result) override;
	void on_readlink(sftp::call_handle, sftp::readlink_data result) override;
	void on_symlink(sftp::call_handle, sftp::symlink_data result) override;
	void on_realpath(sftp::call_handle, sftp::realpath_data result) override;
	void on_extended(sftp::call_handle, sftp::extended_data result) override;

private:
	event_handler& handler_;
	test_client_config const& test_config_;
	channel_id channel_id_{};

	std::function<void()> success_cb_;
	std::function<void()> fail_cb_;
};

}

#endif