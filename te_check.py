#!/usr/bin/python3
import shutil
import os
import subprocess as sp
from sblast import SBlast
from vtotal import VTotal
from time import sleep
from pprint import pprint
from typing import List, Optional, Dict
from check_lists import filetypes, av_set

# Defining main variables
cp_api_key: str = ""
cp_url: str = "https://te.checkpoint.com/tecloud/api/v1/file"

vt_api_key: str = ""
vt_query: str = "size:15MB- "
malware_dir: str = os.path.expanduser("~/malware/")

image_dict = {
    1: "Microsoft Windows: XP - 32bit SP3, Office: 2003, 2007",
    2: "Microsoft Windows: 7 - 32bit, Office: 2003, 2007",
    3: "Microsoft Windows: 7 - 32bit, Office: 2010",
    4: "Microsoft Windows: 7 - 32bit, Office: 2013",
    5: "Microsoft Windows: 7 - 64bit, Office: 2013 (32bit)",
    6: "Microsoft Windows: 8.1 - 64bit, Office: 2013 (64bit)",
    7: "Microsoft Windows: 10, Office: Professional Plus 2016 en-us",
}

# Start interaction with end user to define VT query
while True:
    try:
        file_num: int = int(input("How many files do you need to inspect? "))
        if file_num < 1:
            raise ValueError
        break
    except ValueError:
        print("Value should be positive INT")

filetype: Optional[str] = None
while filetype not in filetypes:
    filetype = input(
        "What file type would you need to inspect (peexe, pdf, doc, etc)? "
    )
    if filetype:
        vt_query += "type:" + filetype + " "
    else:
        print("Wrong file type!")
        continue
    if filetype in ["doc", "docx"]:
        vt_query += 'AND not name: "vbaProject.bin" AND not name:".adp" '
print("And now we need to define antivirus detections")
print(
    "https://support.virustotal.com/hc/en-us/articles/360001385857-Identifying-files-according-to-antivirus-detections"
)
while True:
    av_clean: str = input(
        "Input AV engines according to documentaion names, divided by commas, which should be CLEAN: "
    )
    if av_clean:
        av_clean_list: List[str] = av_clean.split(",")
        av_clean_list = [i.lstrip() for i in av_clean_list]
        if set(av_clean_list).issubset(av_set):
            for i in av_clean_list:
                vt_query += i + ":clean "
            break
        else:
            print("Wrong antivirus definition!")

engines: str = input(
    "Optional - input malware families separated by comma, e.g. ransom, maze: "
)
if engines:
    engines_list: List[str] = engines.split(",")
    for i in engines_list:
        vt_query += "engines:" + i + " "
while True:
    try:
        positives_plus: int = int(
            input("How many AV should detect file as malicious(at least)? ")
        )
        if positives_plus < 1:
            raise ValueError
        vt_query += "p:" + str(positives_plus) + "+ "
        break
    except ValueError:
        print("Value should be positive INT")

while True:
    try:
        positives_minus: int = int(
            input("How many AV should detect file as malicious(max)? ")
        )
        if positives_minus < 1 or positives_minus <= positives_plus:
            raise ValueError
        vt_query += "p:" + str(positives_minus) + "- "
        break
    except ValueError:
        print("Value should be positive INT and not bigger then previous value")


print(f"Current query to VirusTotal is {vt_query}")
vt_query += input("Would you like to add something to the query(e.g. lang:russian)?: ")
pprint(image_dict)
images: Optional[str] = None
while True:
    try:
        images = input("What images would you need to emulate files in? (e.g. 1,2,7) ")
        img_list: List[str] = images.split(",")
        for i in img_list:
            if int(i) in range(1, 8):
                pass
            else:
                raise ValueError
        break
    except ValueError:
        print(
            "Wrong values, they should be in range between 1-7 and separated by commas"
        )
img_int_list: List[int] = [int(i) for i in img_list]

# End interaction with end user to define VT query

# Flushing malware cache and creating directories for new files
if os.path.exists(malware_dir):
    print(f"Flushing {malware_dir}")
    shutil.rmtree(malware_dir)
print("Creating directories for malware files")
os.mkdir(malware_dir)
os.mkdir(f"{malware_dir}/high/")
os.mkdir(f"{malware_dir}/medium/")
os.mkdir(f"{malware_dir}/low/")


vt_service = VTotal(vt_api_key)
print(f"Your query is {vt_query}")
vt_list: List[Dict[str, str]] = vt_service.query(
    vt_query, file_num
)  # Virus Total files query
print(f"{len(vt_list)} files catched")  # display catch

# Download catch to malware directory
for i in vt_list:
    vt_service.download(malware_dir, i["filename"], i["sha1"])

# Creating instances to emulate files
sblasts: Dict[str, any] = {
    i["sha1"]: SBlast(
        f"{malware_dir}{i['filename']}", cp_url, cp_api_key, images=img_int_list
    )
    for i in vt_list
}
results: List[Dict] = []  # List for final results to sort
real_malfiles: int = 0
for i in sblasts.values():
    i.upload()
    if i.te_cache:
        results.append(
            {
                "filename": i.filename,
                "malicious": i.isMalicious,
                "confidence": i.te_confidence,
                "sha1": i.sha1,
            }
        )
        print(f"Currently we have {len(results)} emulated file(s)")
        if i.isMalicious:
            if i.te_confidence >= 2:
                real_malfiles += 1
        print(f"And we have {real_malfiles} good file(s) for further steps")
# Waiting for emulation verdicts
print(
    "Start to query SandBlast service for verdicts. You can stop script running with Ctrl+C when you decide that there is enough files"
)
for i in sblasts.values():
    try:
        while not i.te_cache:
            try:
                i.query()
                print(i.filename)
                if i.te_cache:
                    results.append(
                        {
                            "filename": i.filename,
                            "malicious": i.isMalicious,
                            "confidence": i.te_confidence,
                            "sha1": i.sha1,
                        }
                    )
                    print(f"Currently we have {len(results)} emulated files")
                    if i.isMalicious:
                        if i.te_confidence >= 3:
                            real_malfiles += 1
                    print(f"And we have {real_malfiles} good files for further steps")
                sleep(5)
            except ConnectionError:  # exception for files which have no emulation result(label - NOT FOUND)
                os.remove(str(i.filename))
                print(f"File {i.filename} was removed")
                continue
    except KeyboardInterrupt:
        break


high_confidence_dir = malware_dir + "high"
medium_confidence_dir = malware_dir + "medium"
low_confidence_dir = malware_dir + "low"

for i in results:
    if i["confidence"] == 3:
        os.replace(
            f"{i['filename']}", f"{high_confidence_dir}/{i['filename'].split('/')[-1]}"
        )
    elif i["confidence"] == 2:
        os.replace(
            f"{i['filename']}",
            f"{medium_confidence_dir}/{i['filename'].split('/')[-1]}",
        )
    elif i["confidence"] == 1:
        os.replace(
            f"{i['filename']}", f"{low_confidence_dir}/{i['filename'].split('/')[-1]}"
        )

# Calculating final results
print(f"High confidence files: {len(os.listdir(high_confidence_dir))}")
print(f"Medium confidence files: {len(os.listdir(medium_confidence_dir))}")
print(f"Low confidence files: {len(os.listdir(low_confidence_dir))}")
benign_files = [f for f in os.listdir(malware_dir) if os.path.isfile(malware_dir + f)]
print(f"Still benign files: {len(benign_files)}")
print(
    f'And now you can create password protected archive with the following command: "zip -re malware.zip {high_confidence_dir} {medium_confidence_dir}"'
)
vt_sha1_list = [i["sha1"] for i in results if i["confidence"] in [2, 3]]
if vt_sha1_list:
    choice: str = input(
        "Would you need a web link to download high and medium severity malware files in password protected arcive? [Y/n] "
    )
    if choice in ["y", "Y"]:
        password: str = ""
        while not password:
            password = input("Input your password for archive file: ")
        zip_id: str = vt_service.zip_files(password, vt_sha1_list)
        while True:
            status = vt_service.zip_files_query(zip_id)
            if status == "finished":
                break
        print(
            f"You can download the malware within 1 hour: {vt_service.download_url(zip_id)}"
        )
