@load base/frameworks/notice
@load base/protocols/smb
@load base/frameworks/sumstats

export {
        redef enum Notice::Type += {
        	SMB::Admin_Share_Connection,
        };
}

event bro_init() {
	local r1 = SumStats::Reducer($stream="admin.share.connect",$apply=set(SumStats::SUM));

	SumStats::create([$name="admin.share.connect",
			  $epoch=15mins,
			  $reducers=set(r1),
			  $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
			  	return result["admin.share.connect"]$num+0.0;
			  },
			  $threshold=3.0,
			  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
			  	local r = result["admin.share.connect"];
			  	print fmt("%s had at least %d connection(s) to admin shares (IPC$, ADMIN$, or C$) in 15 mins.",key$host,r$num);
			  }]);
}

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, path: string) {
	if ("IPC$" in path || "ADMIN$" in path || "C$" in path) {
		SumStats::observe("admin.share.connect", [$host=c$id$resp_h], [$str=c$ntlm$server_dns_computer_name]);
	}
}

event smb1_tree_connect_andx_request(c: connection, hdr: SMB1::Header, path: string, service: string) {
	if ("IPC$" in path || "ADMIN$" in path || "C$" in path) {
		SumStats::observe("admin.share.connect", [$host=c$id$resp_h], [$str=c$ntlm$server_dns_computer_name]);
	}
}
