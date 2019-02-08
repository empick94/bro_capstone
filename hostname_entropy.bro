@load base/frameworks/notice 
@load base/protocols/smb

redef record NTLM::Info += {
	hostname_entropy: double &optional &log;
};

event ntlm_authenticate(c: connection, request: NTLM::Authenticate) 
{
	if ( request?$workstation ) {
		local workstation =  request$workstation;
		local y = find_entropy(workstation);
		c$ntlm$hostname_entropy = y$entropy;
	}
}

