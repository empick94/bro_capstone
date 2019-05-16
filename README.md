# bro_capstone

This repository contains deliverables for our MISM capstone project, including:

* Packet captures we generated of normal protocol behavior and attempted exploits
* Static alerts that we wrote for Zeek
* Jupyter notebooks for some of our machine learning work

The major processes, findings, and key learnings of our project are detailed in our project report.

## Bro Scripts

### admin_share_sumstat.bro

This script uses sumstats calculate the number of times a unique host has its admin shares accessed within 10 seconds. If the threshold is crossed in the given timeframe, an alert is written to the notice log that provides details of the event and the IP address of the response host. This script is ready for deployement, but the timeframe and threshold may need to be tuned to the environment.  

### detect_smb_scan.bro

This script uses sumstat to detect smb scanning and enumeration activity. This script focuses on the number of QueryInformationPolicy and SamrGetDomainPasswordInformation requests made to a host within a minute. This alert was created and tuned by analyzing packet captures using enumeration tools such as enum4linux as well as packet captures from normal smb behavior. This alert is ready for deployment.

### filename_entropy.bro

The filename_entropy.bro script uses the same built-in Zeek entropy calculations mentioned above to calculate the entropy for each file name found in the smb_files log. The entropy score is logged out to to a new column in the smb_files log named filename_entropy. There is currently no notice in this script since many normal files can be downloaded with highly entropic names. However, having this field in the smb_files log allows the entropy score to easily be used as part of a threat hunting process. This alert is ready for deployment, but may need to be run against additional events to catch every file.

### hostname_entropy.bro

The existing NTLM log from Zeek contains a hostname for each NTLM event, if a hostname can be found. Many tools used to perform attacks, such as pass-the-hash, generate a random hostname. The hostname_entropy.bro script uses a built-in function within Zeek to calculate the entropy of each hostname and add the entropy score to the ntlm log. Then, create a notice is written if the entropy crosses a threshold. The thresholds are based on the length of the hostname. This was done because longer hostnames tend to have higher entropy in general, so different thresholds are needed for different hostname lengths. This script is ready for deployment, but the threshold information may be better suited as part of another system.

### no_session_key.bro

Some variations of the pass-the-hash attack will result in a successful NTLM event without a session key. Even if the lack of a session key is not from a pass-the-hash attack specifically, protocol documentation shows a session key should always be present and this traffic should still be investigated. The no_session_key.bro script checks for the lack of a session key through the NTLM authentication process. An notice is written to the notice log when a session key is not found. This script is ready for deployment. 

### ntlm_blank_user.bro

NTLM may allow for anonymous logon sessions depending on your domain settings. Enabling anonymous logons increases convenience for users while decreasing security posture (for example, allowing anyone to enumerate file shares or printers). This type of logon is accomplished when sending a blank string as the username. The ntlm_blank_user.bro script checks for blank strings in the username field and writes to the notice log if one is seen. While this alone is not enough to be classified as malicious, writing to the notice log allows visibility into how often anonymous logons occur on a network. The script could also be changed to enhance the existing NTLM log or create an entirely new log. This script is ready for deployment. 

### smb_file_open.bro

By default, Zeek provides limited information on what action was taken on a file accessed over SMB. These default categories are FILE_OPEN, FILE_RENAME, and FILE_DELETE. Many of the events seen in this log have an action of FILE_OPEN without further detail of whether that file was just created, edited, or read. Smb_file_open_type.bro seeks to provide greater detail on the action that has happened to the file on a FILE_OPEN action. This script uses timestamps on the file for last_accessed, last_changed, last_modified, and last_created to create a new column in the smb_file log called smb_file_open_type which can either be ACCESSED, CHANGED, MODIFIED, or CREATED. This script is ready for testing on dev and only is looking at smb2 events. We did see reference to this type of information being present in the Zeek source code (https://github.com/bro/bro/blob/master/scripts/base/protocols/smb/main.zeek, lines 14-33) but we found this  after we had written this script and we did not have time to see if additional detail to the logging can be turned on from the source code itself. If so, Zeek's detailed logging should be used instead of this script. 
