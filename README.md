# cp_sblast_te_check
This script has a purpose to get files from VirusTotal according to user request, then emulate them in CheckPoint SandBlast service in different OS images and finnaly to sort them according to verdicts and confidence levels.

To work with script, you should insert into te_check.py file your VT API key and Check Point TE API key into values vt_api_key and cp_api_key accordingly.
After that, you can run "te_check.py" script on your machine. This script will use SBlast and VTotal classes which are part of the repository.

After short and user-friendly interaction in CLI with user the script will start to download files from VT and emulate them in Check Point SandBlast service until verdict will be returned. When the script will finish it's routine you have two options to get files:
1. Create archive with zip command like "zip -re malware.zip ~/malware/high/ ~/malware/medium". Performing this command will prompt a user for password to create password-protected archive zip file. Then you can get it via SCP.
2. When main routine will be finished, the script will ask a user to create password protected archive using VT API. Be aware, that VT will not include extensions into filenames! If you confirm to create the archive, the script will return web link which will be available within 1 hour.

You can try both ways to get files at one script run.
