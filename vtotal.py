import requests
import json
from typing import List, Dict


class VTotal:
    def __init__(self, key: str) -> None:
        self.url = "https://www.virustotal.com/api/v3"
        self.key = key
        self.headers = {"x-apikey": self.key}

    def query(self, squery: str, count: int) -> List[Dict[str, str]]:
        response = requests.get(
            url=f"{self.url}/intelligence/search?query={squery}&limit={count}",
            headers=self.headers,
        )
        response_j = response.json()
        filelist = []
        for i in response_j["data"]:
            sha1 = i["attributes"]["sha1"]
            filename = f"{sha1}.{i['attributes']['type_extension']}"
            filelist.append({"sha1": sha1, "filename": filename})
        return filelist

    def zip_files(self, password: str, hashes: List) -> str:
        data_dict = {"data": {"password": password, "hashes": hashes}}
        response = requests.post(
            url=f"{self.url}/intelligence/zip_files",
            headers=self.headers,
            data=json.dumps(data_dict),
        )
        response_j = response.json()
        return response_j["data"]["id"]

    def zip_files_query(self, zip_id: str):
        response = requests.get(
            url=f"{self.url}/intelligence/zip_files/{zip_id}", headers=self.headers
        )
        response_j = response.json()
        print(
            f'Status: {response_j["data"]["attributes"]["status"]}, Progress: {response_j["data"]["attributes"]["progress"]}%, Ready files: {response_j["data"]["attributes"]["files_ok"]}'
        )
        return response_j["data"]["attributes"]["status"]

    def download(self, directory: str, filename: str, sha1: str) -> str:
        print(f"Starting to download {filename}")
        response = requests.get(
            url=f"{self.url}/files/{sha1}/download", headers=self.headers
        )
        if response.ok:
            print(f"File {filename} downloaded successfully")
        with open(f"{directory}{filename}", "wb") as f:
            f.write(response.content)
        return f"{directory}{filename}"

    def download_url(self, zip_id: str):
        response = requests.get(
            url=f"{self.url}/intelligence/zip_files/{zip_id}/download_url",
            headers=self.headers,
        )
        response_j = response.json()
        return response_j["data"]
