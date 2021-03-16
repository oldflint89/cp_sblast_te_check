import requests
import json
import hashlib
import base64
from typing import Optional, Dict, List


class SBlast:
    def __init__(
        self, filename: str, url: str, key: str, images: List[int] = [1, 4]
    ) -> None:
        self.filename: str = filename
        self.url: str = url
        self.key: str = key
        self.headers: Dict[str, str] = {"Authorization": self.key}
        self.md5: Optional[str] = None
        self.sha1: Optional[str] = None
        self.sha256: Optional[str] = None
        self.te_cache: bool = False
        self.isMalicious: Optional[bool] = None
        self.isBenign: Optional[bool] = None
        self.te_confidence: Optional[int] = None
        images_dict = {
            1: {"id": "e50e99f3-5963-4573-af9e-e3f4750b55e2", "revision": 1},
            2: {"id": "7e6fe36e-889e-4c25-8704-56378f0830df", "revision": 1},
            3: {"id": "8d188031-1010-4466-828b-0cd13d4303ff", "revision": 1},
            4: {"id": "5e5de275-a103-4f67-b55b-47532918fa59", "revision": 1},
            5: {"id": "3ff3ddae-e7fd-4969-818c-d5f1a2be336d", "revision": 1},
            6: {"id": "6c453c9b-20f7-471a-956c-3198a868dc92", "revision": 1},
            7: {"id": "10b4a9c6-e414-425c-ae8b-fe4dd7b25244", "revision": 1},
        }
        images_list = [images_dict[i] for i in images]
        self.request = {
            "request": [{"features": ["te"], "te": {"images": images_list}}]
        }

    def __str__(self):
        return f"CP Threat Emulation data for {self.filename}"

    def __repr__(self):
        return f"{self.filename} CP TE data"

    def query(self, verbose: bool = False) -> None:
        """
        This class method will query SandBlast service for verdict and confidence(if file recognized as malicious)
        In case of timeout in SandBlast service with no verdict, it will raise ConnectionError
        """
        if not self.sha1:
            with open(self.filename, "rb") as f:
                content = f.read()
                self.sha1 = hashlib.sha1(content).hexdigest()
        request = self.request
        request["request"][0].update({"sha1": self.sha1})
        data = json.dumps(request)
        if verbose:
            print(f"request: {data}")
        try:
            response = requests.post(
                url=f"{self.url}/query", headers=self.headers, data=data
            )
            response_j = response.json()
            if verbose:
                print(f"response: {response_j}")
            print(
                f"File {self.filename} status: {response_j['response'][0]['te']['status']['label']}"
            )
            if response_j["response"][0]["te"]["status"]["label"] == "FOUND":
                self.te_cache = True
                if response_j["response"][0]["te"]["combined_verdict"] == "malicious":
                    self.isMalicious = True
                    self.isBenign = False
                    self.te_confidence = int(
                        response_j["response"][0]["te"]["confidence"]
                    )
                elif response_j["response"][0]["te"]["combined_verdict"] == "benign":
                    self.isMalicious = False
                    self.isBenign = True
            elif response_j["response"][0]["te"]["status"]["label"] == "NOT_FOUND":
                raise ConnectionError("Upload file first")
        except requests.exceptions.ConnectionError:
            print("CONNECTION ERROR!!!")

    def upload(self, verbose: bool = False) -> None:
        """
        This class method will upload file to SandBlast service, and if cache is known fill class variables such as verdict, confidence and file hashes
        """
        data = json.dumps(self.request)
        if verbose:
            print(f"request: {data}")
        headers = {"Authorization": self.key}
        curr_file = {"request": data, "file": open(self.filename, "rb")}
        print(f"Start to upload {self.filename}")
        try:
            response = requests.post(
                url=f"{self.url}/upload", headers=self.headers, files=curr_file
            )
            if response.status_code == 200:
                print(response.status_code)
                response_j = response.json()
                if verbose:
                    print(f"response: {response_j}")
                if response_j["response"]["status"]["label"] == "FOUND":
                    print(f"Verdict for {self.filename} found")
                    self.md5 = response_j["response"]["md5"]
                    self.sha1 = response_j["response"]["sha1"]
                    self.sha256 = response_j["response"]["sha256"]
                    self.te_cache = True
                    if response_j["response"]["te"]["combined_verdict"] == "malicious":
                        self.isMalicious = True
                        self.isBenign = False
                        self.te_confidence = int(
                            response_j["response"]["te"]["confidence"]
                        )
                    elif response_j["response"]["te"]["combined_verdict"] == "benign":
                        self.isMalicious = False
                        self.isBenign = True
            else:
                print(response.status_code)
        except requests.exceptions.ConnectionError:
            print("CONNECTION ERROR!!!")
