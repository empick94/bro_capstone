@load base/frameworks/files
@load base/frameworks/notice
@load frameworks/files/hash-all-files

export {
    redef enum Notice::Type += {
        FILES::Virustotal_Hit
    };


	# url needed to use VirusTotal API
    const vt_url = "https://www.virustotal.com/vtapi/v2/file/report" &redef;
    
    # VirusTotal API key
    const vt_apikey = "enter in your VirusTotal public or private API key here" &redef;
    
    # threshold of Anti-Virus hits that must be met to trigger an alert
    const notice_threshold = 3 &redef;

}

# keep list of checked & matched
global checked_hashes: set[string];
global bad_hashes: set[string];

function do_lookup(hash: string)
{
	local data = fmt("resource=%s", hash);
        local key = fmt("-d apikey=%s",vt_apikey);
        # HTTP request out to VirusTotal via API
        local req: ActiveHTTP::Request = ActiveHTTP::Request($url=vt_url, $method="POST",$client_data=data, $addl_curl_args=key);
        when (local res = ActiveHTTP::request(req))
        {
                if ( |res| > 0)
                {
                        if ( res?$body )
                        {
                                local body = res$body;
                                local tmp = split_string(res$body,/\}\},/);
                                if ( |tmp| != 0 )
                                {
                                        local stuff = split_string( tmp[1], /\,/ );
                                        # splitting the string that contains the amount of positive anti-virus hits on ":" "positives:23"
                                        local pos = split_string(stuff[9],/\:/);
                                        # converting the string from variable pos into a integer
                                        local notic = to_int(pos[1]);
                                        # If the number of positives (number stored in variable notic) equals or exceeds the threshold, generate a notice
                                        if (notic >= notice_threshold ) {
						NOTICE([$note=FILES::Virustotal_Hit,
						$msg = fmt("%s has 3 or more detections on Virustotal",hash),
						$sub = stuff[6]]);

						add(bad_hashes[hash]);
                                        }
					else {
						add(checked_hashes[hash]);
					}
                                }
                        }
                }
	}
}

event bro_init() {
	local r1 = SumStats::Reducer($stream="admin.share.connect",$apply=set(SumStats::TOPK));
	
	SumStats::create([$name="virustotal.check",
			$epoch=15secs,
			$reducers=set(r1),
			$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
				local r = result["virustotal.check"];
                        	local s: vector of SumStats::Observation;
                        	s = topk_get_top(r$topk, 100);
				for ( i in s ) {
					if ( ! (s[i]$str in checked_hashes) ) {
						do_lookup(s[i]$str);
					}
				}
			}]);
}

event file_hash(f: fa_file, kind: string, hash: string)
{
	# If the file "f" for the event has a source type, and if the source type equals SMB, check file hash against VirusTotal
	if ( f?$source && f$source == "SMB" )
	{
		if ( hash in bad_hashes ) {
			local msg = "Previously scanned hash with 3 detections or more on Virustotal";
                        local n: Notice::Info = Notice::Info($note=FILES::Virustotal_Hit, $msg=msg, $sub=hash);
                        Notice::populate_file_info2(Notice::create_file_info(f), n);
                        NOTICE(n);
		}
		else {
			SumStats::observe("virustotal.check", [], [$str=hash]);
		}
	}
       
}
