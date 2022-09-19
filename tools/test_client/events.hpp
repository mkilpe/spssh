#ifndef SP_SSH_TOOLS_TEST_CLIENT_EVENTS_HEADER
#define SP_SSH_TOOLS_TEST_CLIENT_EVENTS_HEADER

namespace securepath::ssh::events {

/// prompt command from user
struct command_prompt {
	typedef void type();
};

}

#endif