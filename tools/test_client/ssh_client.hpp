#ifndef SP_SSH_TOOLS_TEST_CLIENT_SSH_CLIENT_HEADER
#define SP_SSH_TOOLS_TEST_CLIENT_SSH_CLIENT_HEADER

#include "client_config.hpp"
#include "ssh/client/ssh_client.hpp"
#include "ssh/services/sftp/sftp_client_interface.hpp"
#include "tools/common/event_handler.hpp"

namespace securepath::ssh {

using sftp::sftp_result;

class ssh_test_client : public ssh_client, public sftp::sftp_client_callback {
public:
	ssh_test_client(event_handler& handler, test_client_config const&, logger& log, out_buffer&, crypto_context = default_crypto_context());

protected:
	handler_result handle_kex_done(kex const&) override;

	void on_service_started() override;

protected:
	bool on_version(std::uint32_t version, sftp::ext_data_view data) override;
	void on_open_file(sftp_result<sftp::open_file_data> result) override;
	void on_read_file(sftp_result<sftp::read_file_data> result) override;
	void on_write_file(sftp_result<sftp::write_file_data> result) override;
	void on_close_file(sftp_result<sftp::close_file_data> result) override;
	void on_open_dir(sftp_result<sftp::open_file_data> result) override;
	void on_read_dir(sftp_result<sftp::read_dir_data> result) override;
	void on_close_dir(sftp_result<sftp::close_dir_data> result) override;

private:
	event_handler& handler_;
	test_client_config const& test_config_;
};

}

#endif