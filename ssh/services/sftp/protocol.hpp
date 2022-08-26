#ifndef SP_SSH_SFTP_PROTOCOL_HEADER
#define SP_SSH_SFTP_PROTOCOL_HEADER

#include "packet_ser.hpp"

namespace securepath::ssh::sftp {

/*
	The SSH_FXP_INIT packet (from client to server) has the following
	data:
		uint32 version
		<extension data>
*/
using init = sftp_packet_ser
<
	fxp_init,
	ser::uint32
>;

/*
	The SSH_FXP_VERSION packet (from server to client) has the following
	data:
		uint32 version
		<extension data>
*/
using version = sftp_packet_ser
<
	fxp_version,
	ser::uint32
>;

/////// requests

/*
	the SSH_FXP_OPEN message
		uint32        id
		string        filename
		uint32        pflags
		ATTRS         attrs
*/
using open_request = sftp_packet_ser
<
	fxp_open,
	ser::uint32,
	ser::string,
	ser::uint32,
	ser::uint32 /*attribute flags, rest of the attributes are read/written separately based on this*/
>;

/*
	the SSH_FXP_CLOSE request.
		uint32     id
		string     handle
*/
using close_request = sftp_packet_ser
<
	fxp_close,
	ser::uint32,
	ser::string
>;

/*
	the SSH_FXP_READ message
		uint32     id
		string     handle
		uint64     offset
		uint32     len
*/
using read_request = sftp_packet_ser
<
	fxp_read,
	ser::uint32,
	ser::string,
	ser::uint64,
	ser::uint32
>;

/*
	the SSH_FXP_WRITE message
		uint32     id
		string     handle
		uint64     offset
		string     data
*/
using write_request = sftp_packet_ser
<
	fxp_write,
	ser::uint32,
	ser::string,
	ser::uint64,
	ser::string
>;

/*
	the SSH_FXP_REMOVE message
		uint32     id
		string     filename
*/
using remove_request = sftp_packet_ser
<
	fxp_remove,
	ser::uint32,
	ser::string
>;

/*
	the SSH_FXP_RENAME message
		uint32     id
		string     oldpath
		string     newpath
*/
using rename_request = sftp_packet_ser
<
	fxp_rename,
	ser::uint32,
	ser::string,
	ser::string
>;

/*
	the SSH_FXP_MKDIR request
		uint32     id
		string     path
		ATTRS      attrs
*/
using mkdir_request = sftp_packet_ser
<
	fxp_mkdir,
	ser::uint32,
	ser::string,
	ser::uint32 /*attribute flags, rest of the attributes are read/written separately based on this*/
>;

/*
	SSH_FXP_RMDIR request
		uint32     id
		string     path
*/
using rmdir_request = sftp_packet_ser
<
	fxp_rmdir,
	ser::uint32,
	ser::string
>;

/*
	The SSH_FXP_OPENDIR opens a directory for reading
		uint32     id
		string     path
*/
using opendir_request = sftp_packet_ser
<
	fxp_opendir,
	ser::uint32,
	ser::string
>;

/*
	the SSH_FXP_READDIR requests
		uint32     id
		string     handle
*/
using readdir_request = sftp_packet_ser
<
	fxp_readdir,
	ser::uint32,
	ser::string
>;

/*
	the SSH_FXP_STAT (follows symbolic links on the server)
		uint32     id
		string     path
*/
using stat_request = sftp_packet_ser
<
	fxp_stat,
	ser::uint32,
	ser::string
>;

/*
	the SSH_FXP_LSTAT (does _not_ follow symbolic links on the server)
		uint32     id
		string     path
*/
using lstat_request = sftp_packet_ser
<
	fxp_lstat,
	ser::uint32,
	ser::string
>;

/*
	the SSH_FXP_FSTAT (stat for open file)
		uint32     id
		string     handle
*/
using fstat_request = sftp_packet_ser
<
	fxp_fstat,
	ser::uint32,
	ser::string
>;

/*
	The SSH_FXP_SETSTAT request
		uint32     id
		string     path
		ATTRS      attrs
*/
using setstat_request = sftp_packet_ser
<
	fxp_setstat,
	ser::uint32,
	ser::string,
	ser::uint32 /*attribute flags, rest of the attributes are read/written separately based on this*/
>;

/*
	The SSH_FXP_FSETSTAT request
		uint32     id
		string     handle
		ATTRS      attrs
*/
using fsetstat_request = sftp_packet_ser
<
	fxp_fsetstat,
	ser::uint32,
	ser::string,
	ser::uint32 /*attribute flags, rest of the attributes are read/written separately based on this*/
>;

/*
	The SSH_FXP_READLINK request
		uint32     id
		string     path
*/
using readlink_request = sftp_packet_ser
<
	fxp_readlink,
	ser::uint32,
	ser::string
>;

/*
	The SSH_FXP_SYMLINK request will create a symbolic link
		uint32     id
		string     linkpath
		string     targetpath
*/
using symlink_request = sftp_packet_ser
<
	fxp_symlink,
	ser::uint32,
	ser::string,
	ser::string
>;

/*
	The SSH_FXP_REALPATH request can be used to have the server
	canonicalize any given path name to an absolute path.
		uint32     id
		string     path
*/
using realpath_request = sftp_packet_ser
<
	fxp_realpath,
	ser::uint32,
	ser::string
>;

/*
	The SSH_FXP_EXTENDED request provides a generic extension mechanism
	for adding vendor-specific commands.
		uint32     id
		string     extended-request
		... any request-specific data ...
*/
using extended_request = sftp_packet_ser
<
	fxp_extended,
	ser::uint32,
	ser::string
>;

////////// Responses

/*
	the SSH_FXP_STATUS response
		uint32     id
		uint32     error/status code
		string     error message (ISO-10646 UTF-8 [RFC-2279])
		string     language tag (as defined in [RFC-1766])
*/

using status_response = sftp_packet_ser
<
	fxp_status,
	ser::uint32,
	ser::uint32,
	ser::string,
	ser::string
>;

/*
	The SSH_FXP_HANDLE response
		uint32     id
		string     handle
*/
using handle_response = sftp_packet_ser
<
	fxp_handle,
	ser::uint32,
	ser::string
>;

/*
	The SSH_FXP_DATA response
		uint32     id
		string     data
*/
using data_response = sftp_packet_ser
<
	fxp_data,
	ser::uint32,
	ser::string
>;

/*
	The SSH_FXP_NAME response
		uint32     id
		uint32     count
		repeats count times:
				string     filename
				string     longname
				ATTRS      attrs
*/
using name_response = sftp_packet_ser
<
	fxp_name,
	ser::uint32,
	ser::uint32
>;

/*
	The SSH_FXP_ATTRS response
		uint32     id
		ATTRS      attrs
*/
using attrs_response = sftp_packet_ser
<
	fxp_attrs,
	ser::uint32,
	ser::uint32 /*attribute flags, rest of the attributes are read/written separately based on this*/
>;

/*
	The SSH_FXP_EXTENDED_REPLY packet can be used to carry arbitrary
	extension-specific data from the server to the client.
		uint32     id
		... any request-specific data ...
*/
using extended_reply_response = sftp_packet_ser
<
	fxp_attrs,
	ser::uint32
>;

}

#endif