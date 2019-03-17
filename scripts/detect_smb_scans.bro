@load base/frameworks/notice
@load base/protocols/smb
@load base/frameworks/sumstats
@load base/protocols/dce-rpc

export {
        redef enum Notice::Type += {
		SMB::Lsa_Query_Info_Policy,
		SMB::Lsar_Password_Information
        };
}

event bro_init() {
	local r1 = SumStats::Reducer($stream="lsa.queryinfopolicy",$apply=set(SumStats::SUM));

	SumStats::create([$name="lsa.queryinfopolicy",
			  $epoch=60secs,
			  $reducers=set(r1),
			  $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
				return result["lsa.queryinfopolicy"]$num+0.0;
			  },
			  $threshold=10.0,
			  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
			    local r = result["lsa.queryinfopolicy"];
			    NOTICE([$note=SMB::Lsa_Query_Info_Policy,
			     $msg = fmt("%s made at least 10 QueryInformationPolicy requests in 60 seconds.",key$host),
			     $sub = fmt("%s made at least %d QueryInformationPolicy requests in 60 seconds indicating potentially malicous scanning.",key$host,r$num)]);
			  }]);
}

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count){
	if ( c?$dce_rpc ){
		#Observe each use of the dce_rpc operation LsarQueryInformationPolicy, grouped by orig_h
		if (c$dce_rpc$operation == "LsarQueryInformationPolicy"){
			SumStats::observe("lsa.queryinfopolicy", SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
		}
		 
		#Alert when the operation SamrGetDomainPasswordInformation is seen. High likelihood that it's from a scanning tool
		if (c$dce_rpc$operation == "SamrGetDomainPasswordInformation"){
			NOTICE([
				$note=SMB::Lsar_Password_Information,
				$msg = fmt("%s made a SamrGetDomainPasswordInformation request.",c$id$orig_h),
				$sub = fmt("%s sent a SamrGetDomainPasswordInformatin request to %s, indicating potentially malicous scanning.",
					    c$id$orig_h, c$id$resp_h),
				$conn = c
				]);
		}
	}
	
}
