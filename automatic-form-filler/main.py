import docx
import re
import requests
import dotenv
import os

def get_fileInfoByHash(fileSha1Hash, VT_API_KEY):
    url = f"https://www.virustotal.com/api/v3/files/{fileSha1Hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": f"{VT_API_KEY}"
    }
    response = requests.get(url, headers=headers)
    return response.text

def get_placeHolders(doc):
    holders = []
    hPattern = re.compile(r'\{\{[\w]+\}\}')
    for para in doc.paragraphs:
        if hPattern.search(para.text):
            holders.extend(hPattern.findall(para.text))
    return holders

def get_env(secret): 
    dotenv.load_dotenv()    
    val = os.getenv(secret)
    if not val:
        raise RuntimeError(f"{secret} not set; Recheck .env file.")
    return val

def main():
    doc = docx.Document("malware_report_template.docx")
    # get_fileInfoByHash(get_env("FILE_SHA1SUM"), get_env("VIRUS_TOTAL_API_KEY"))

if __name__ == "__main__":
    main()

