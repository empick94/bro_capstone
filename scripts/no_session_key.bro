@load base/frameworks/notice
@load base/protocols/smb

export {
	redef enum Notice::Type += {
		NTLM::Empty_Session_Key,
		NTLM::Negotiate_Target_Info
	};
}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate) {
	if ( !request?$session_key ) {
		NOTICE([$note=NTLM::Empty_Session_Key,
		$msg = "Empty session key during NTLM_AUTHENTICATE EVENT",
		$sub = fmt("%s authenticated to %s with no session key", c$id$orig_h, c$id$resp_h),
		$conn = c]);
	}
}

event ntlm_negotiate(c: connection, request: NTLM::Negotiate) {
	if ( request$flags$negotiate_target_info ) {
		NOTICE([$note=NTLM::Negotiate_Target_Info,
                $msg = "negotiate_target_info is true during NTLM NEGOTIATE EVENT",
                $sub = fmt("%s authenticated to %s with while negotiating_target_info equals true in negotiate event", c$id$orig_h, c$id$resp_h),
                $conn = c]);
	}
}
