#ifndef SP_SSH_SFTP_PACKET_TYPES_HEADER
#define SP_SSH_SFTP_PACKET_TYPES_HEADER

namespace securepath::ssh::sftp {

enum sftp_packet_type : std::uint8_t {
	fxp_init           = 1,
	fxp_version        = 2,
	fxp_open           = 3,
	fxp_close          = 4,
	fxp_read           = 5,
	fxp_write          = 6,
	fxp_lstat          = 7,
	fxp_fstat          = 8,
	fxp_setstat        = 9,
	fxp_fsetstat       = 10,
	fxp_opendir        = 11,
	fxp_readdir        = 12,
	fxp_remove         = 13,
	fxp_mkdir          = 14,
	fxp_rmdir          = 15,
	fxp_realpath       = 16,
	fxp_stat           = 17,
	fxp_rename         = 18,
	fxp_readlink       = 19,
	fxp_symlink        = 20,
	fxp_status         = 101,
	fxp_handle         = 102,
	fxp_data           = 103,
	fxp_name           = 104,
	fxp_attrs          = 105,
	fxp_extended       = 200,
	fxp_extended_reply = 201
};

enum attribute_flags : std::uint32_t {
	size_attribute        = 0x00000001,
	uidgid_attribute      = 0x00000002,
	permissions_attribute = 0x00000004,
	acmodtime_attribute   = 0x00000008,
	extended_attribute    = 0x80000000
};

enum open_mode : std::uint32_t {
	fxf_read   = 0x00000001,
	fxf_write  = 0x00000002,
	fxf_append = 0x00000004,
	fxf_creat  = 0x00000008,
	fxf_trunc  = 0x00000010,
	fxf_excl   = 0x00000020
};
/*
   SSH_FXF_READ
      Open the file for reading.

   SSH_FXF_WRITE
      Open the file for writing.  If both this and SSH_FXF_READ are
      specified, the file is opened for both reading and writing.

   SSH_FXF_APPEND
      Force all writes to append data at the end of the file.

   SSH_FXF_CREAT
      If this flag is specified, then a new file will be created if one
      does not already exist (if O_TRUNC is specified, the new file will
      be truncated to zero length if it previously exists).

   SSH_FXF_TRUNC
      Forces an existing file with the same name to be truncated to zero
      length when creating a file by specifying SSH_FXF_CREAT.
      SSH_FXF_CREAT MUST also be specified if this flag is used.

   SSH_FXF_EXCL
      Causes the request to fail if the named file already exists.
      SSH_FXF_CREAT MUST also be specified if this flag is used.
*/

enum status_code : std::uint32_t {
	fx_ok                = 0,
	fx_eof               = 1,
	fx_no_such_file      = 2,
	fx_permission_denied = 3,
	fx_failure           = 4,
	fx_bad_message       = 5,
	fx_no_connection     = 6,
	fx_connection_lost   = 7,
	fx_op_unsupported    = 8
};
/*
  SSH_FX_OK
      Indicates successful completion of the operation.

   SSH_FX_EOF
      indicates end-of-file condition; for SSH_FX_READ it means that no
      more data is available in the file, and for SSH_FX_READDIR it
      indicates that no more files are contained in the directory.

   SSH_FX_NO_SUCH_FILE
      is returned when a reference is made to a file which should exist
      but doesn't.

   SSH_FX_PERMISSION_DENIED
      is returned when the authenticated user does not have sufficient
      permissions to perform the operation.

   SSH_FX_FAILURE
      is a generic catch-all error message; it should be returned if an
      error occurs for which there is no more specific error code
      defined.

   SSH_FX_BAD_MESSAGE
      may be returned if a badly formatted packet or protocol
      incompatibility is detected.

   SSH_FX_NO_CONNECTION
      is a pseudo-error which indicates that the client has no
      connection to the server (it can only be generated locally by the
      client, and MUST NOT be returned by servers).

   SSH_FX_CONNECTION_LOST
      is a pseudo-error which indicates that the connection to the
      server has been lost (it can only be generated locally by the
      client, and MUST NOT be returned by servers).

   SSH_FX_OP_UNSUPPORTED
      indicates that an attempt was made to perform an operation which
      is not supported for the server (it may be generated locally by
      the client if e.g.  the version number exchange indicates that a
      required feature is not supported by the server, or it may be
      returned by the server if the server does not implement an
      operation).
*/


}

#endif