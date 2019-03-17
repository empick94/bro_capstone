@load base/frameworks/notice 
@load base/protocols/smb

redef record NTLM::Info += {
	hostname_entropy: double &optional &log;
};

export {
	redef enum Notice::Type += {
		NTLM::Hostname_Entropy
	};
}

function create_notice(entropy: double, c: connection, request: NTLM::Authenticate) {
	NOTICE([$note = NTLM::Hostname_Entropy,
	$msg = "Hostname is over three standard devations above the norm",
	$sub = fmt("Hostname: %s, Length: %s, Entropy: %s", request$workstation, |request$workstation|, entropy),
	$conn = c]);
}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate) 
{
	if ( request?$workstation ) {
		local workstation =  request$workstation;
		local y = find_entropy(workstation);
		c$ntlm$hostname_entropy = y$entropy;
		

                local hostname_length = |workstation|;

                if ( hostname_length < 6 && y$entropy > 3.038 ) {
                        create_notice(y$entropy, c, request);
                } else if ( hostname_length < 11 && y$entropy > 3.854 ) {
                        create_notice(y$entropy, c, request);
                } else if ( hostname_length < 16 && y$entropy > 4.103 ) {
                        create_notice(y$entropy, c, request);
                } else if ( y$entropy > 4.382 ) {
                        create_notice(y$entropy, c, request);
                }
	}
}

