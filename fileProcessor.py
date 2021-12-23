import hashlib
import requests
import json

class FileProcessor():

    def __init__(self):
        pass

    # This function will compute SHA1 hash value for a given file.
    def computeHash(self, path, filesList):
        hashDigest = []
        # open file for reading in binary mode
        for file in filesList:
            hashValue = hashlib.sha1()
            with open(path + '\\' + file,'rb') as reader:
                # loop till the end of the file
                chunk = 0
                while chunk != b'':
                # read only 1024 bytes=1MB at a time
                    chunk = reader.read(1024)
                    hashValue.update(chunk)
                    hash = hashValue.hexdigest()
            reader.close()
            hashDigest.append({file: hash})

        # return list of the hex representation of digests
        return hashDigest

    # This function will check VirusTotal API for suspicioness of a given hash. 
    def checkHash(self, hashesList):
        hashResults = []
        api_key = 'ENTER YOUR VIRUS TOTAL API KEY HERE!'
        for index in range(len(hashesList)):
            for file, hash in hashesList[index].items():
                params = {'apikey': api_key, 'resource': hash}
                url = requests.get(
                    'https://www.virustotal.com/vtapi/v2/file/report', params=params)
                json_response = url.json()
                x = str(json_response)
                x = x.replace("'", '"')
                x = x.replace("False", '"False"')
                x = x.replace("True", '"True"')
                x = x.replace("None", '"None"')

                parsed = json.loads(x)
                y = json.dumps(parsed, indent=4, sort_keys=True)

                response = int(json_response.get('response_code'))
                if response == 0:
                    malicious = 'Not Found'
                elif response == 1:
                    positives = int(json_response.get('positives'))
                    if positives == 0:
                        malicious = 'Non-Malicious'
                    else:
                        malicious = 'Malicious'
                else:
                    malicious = -2
                hashResults.append({file: malicious})

        return hashResults