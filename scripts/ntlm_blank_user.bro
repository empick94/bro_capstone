@load base/frameworks/notice
@load base/protocols/smb

export {
        redef enum Notice::Type += {
                NTLM::Blank_Username
        };
}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
{
	if (request?$user_name == F)
	{
		NOTICE([
			$note = NTLM::Blank_Username,
			$msg = "Blank Username during NTLM_AUTHENTICATE event",
			$sub = fmt("%s attempted to authenticate to %s with no username", c$id$orig_h, c$id$resp_h),
			$conn = c
		]);
	}
}
