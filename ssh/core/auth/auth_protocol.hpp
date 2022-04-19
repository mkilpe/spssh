#ifndef SP_SHH_AUTH_PROTOCOL_HEADER
#define SP_SHH_AUTH_PROTOCOL_HEADER

#include "ssh/core/packet_ser.hpp"
#include "ssh/core/packet_types.hpp"

namespace securepath::ssh {

enum ecdh_packet_type : std::uint8_t {
	ssh_auth_pk_ok = 60,
	ssh_auth_password_changereq = 60
};

namespace ser {

/*
	byte      SSH_MSG_USERAUTH_REQUEST
	string    user name in ISO-10646 UTF-8 encoding [RFC3629]
	string    service name in US-ASCII
	string    method name in US-ASCII
	....      method specific fields
*/
using userauth_request = ssh_packet_ser
<
	ssh_userauth_request,
	string,
	string,
	string
>;

/*
	byte      SSH_MSG_USERAUTH_REQUEST
	string    user name in ISO-10646 UTF-8 encoding [RFC3629]
	string    service name in US-ASCII
	string    "publickey"
	boolean   FALSE = query, TRUE = authenticate
	string    public key algorithm name
	string    public key blob
	string    signature -- if above boolean is true otherwise nothing
*/
using userauth_pk_request = ssh_packet_ser
<
	ssh_userauth_request,
	string,
	string,
	string,
	boolean,
	string,
	string
>;

/*
	byte      SSH_MSG_USERAUTH_PK_OK
	string    public key algorithm name from the request
	string    public key blob from the request
*/
using userauth_pk_ok = ssh_packet_ser
<
	ssh_auth_pk_ok,
	string,
	string
>;

/*
	byte         SSH_MSG_USERAUTH_FAILURE
	name-list    authentications that can continue
 	boolean      partial success
*/

using userauth_failure = ssh_packet_ser
<
	ssh_userauth_failure,
	name_list,
	boolean
>;

/*
	byte      SSH_MSG_USERAUTH_SUCCESS
*/

using userauth_success = ssh_packet_ser
<
	ssh_userauth_success
>;

/*
	byte      SSH_MSG_USERAUTH_BANNER
	string    message in ISO-10646 UTF-8 encoding [RFC3629]
	string    language tag [RFC3066]
*/
using userauth_banner = ssh_packet_ser
<
	ssh_userauth_banner,
	string,
	string
>;


/*
	byte      SSH_MSG_USERAUTH_REQUEST
	string    user name
	string    service name
	string    "password"
	boolean   FALSE = authenticate, TRUE = change password
	string    plaintext password in ISO-10646 UTF-8 encoding [RFC3629]
	string    new password -- if above boolean is true otherwise nothing
*/
using userauth_password_request = ssh_packet_ser
<
	ssh_userauth_request,
	string,
	string,
	string,
	boolean,
	string
>;

/*
	byte      SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
	string    prompt in ISO-10646 UTF-8 encoding [RFC3629]
	string    language tag [RFC3066]
*/
using userauth_password_changereq = ssh_packet_ser
<
	ssh_auth_password_changereq,
	string,
	string
>;

}
}

#endif