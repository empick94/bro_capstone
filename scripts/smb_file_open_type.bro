@load base/frameworks/notice
@load base/protocols/smb

redef record SMB::FileInfo += {
	smb_file_open_type: string &optional &log;
};


event smb2_create_response(c: connection, hdr: SMB2::Header, response: SMB2::CreateResponse) {
	local t = c$smb_state$current_file$times;
	local cf = c$smb_state$current_file;

	if ( c$smb_state$current_file?$action && c$smb_state$current_file$action == SMB::FILE_OPEN ) {

		if ( time_to_double(cf$ts) - time_to_double(t$accessed) < 2.0 ) {
			c$smb_state$current_file$smb_file_open_type = "ACCESSED";
		}
		if ( time_to_double(cf$ts) - time_to_double(t$changed) < 2.0 ) {
			c$smb_state$current_file$smb_file_open_type = "CHANGED";
		}
		if ( time_to_double(cf$ts) - time_to_double(t$modified) < 2.0 ) {
			c$smb_state$current_file$smb_file_open_type = "MODIFIED";
		}
		if ( t$modified == t$changed && t$modified == t$accessed && t$modified == t$created ) {
			c$smb_state$current_file$smb_file_open_type = "CREATED";
		}
	}
}
