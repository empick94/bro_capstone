
@load base/frameworks/notice
@load base/protocols/smb

redef record SMB::FileInfo += {
        filename_entropy: double &optional &log;
};


event smb2_create_request(c: connection, hdr: SMB2::Header, file_name: string) {
        local x = file_name;
	if ( type_name(x) == "string" ) {
        	local y = split_string(x, /[\\]/);
        	print y;
        	if ( |y| > 0 && /\./ in y[|y| - 1]) {
               		local z = find_entropy(y[|y| - 1]);
               		c$smb_state$current_cmd$referenced_file$filename_entropy = z$entropy;
        	}
	}
}


event smb1_nt_create_andx_request(c: connection, hdr: SMB1::Header, name: string) {
	local x = name;
	if ( /\./ in x ) {
		local y = split_string(x, /[\\]/);
		print y;
		if ( |y| > 0 ) {
			local z = find_entropy(y[|y| - 1]);
			c$smb_state$current_cmd$referenced_file$filename_entropy = z$entropy;
		}
	}
}
