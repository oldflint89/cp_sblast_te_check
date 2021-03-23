# cp_sblast_te_check
This script aims to get files from VirusTotal according to user input, then emulate them in CheckPoint SandBlast service in different OS images and finally sort them according to verdicts and confidence levels. If the script found malicious files, the final step would be creating a password-protected archive with malicious files which have high and medium confidence level.

## Requirements:

Python 3.7 or higher required.

ZIP utility must be installed to create a password-protected archive with malicious files at the end of the script. For Debian/Ubuntu:

`sudo apt install zip`

## Workflow:

To work with the script, you should define your VT API key and Check Point TE API key in te_check.py file. API keys should be defined in cp_api_key and vt_api_key variables accordingly. You can use your own private TE appliances and gateways instead of SandBlast Service in a Cloud, just replace URL address in the cp_url variable. [More information about TE API on local gateways - Accessing the API](https://sc1.checkpoint.com/documents/TPAPI/CP_1.0_ThreatPreventionAPI_APIRefGuide/html_frameset.htm)

After that, you can run "te_check.py" script on your machine. This script will use SBlast and VTotal classes which are part of the repository.

After short interaction in CLI with a user, the script will start to download files from VT and emulate them in Check Point SandBlast service until the verdict is returned. When the script will finish it's routine, and if something malicious would found, the script will ask the user to prompt the password. It would create a password-protected archive file named "malware.zip" in the user's home directory. After that, you can get "malware.zip" archive using, for instance, SCP protocol.
