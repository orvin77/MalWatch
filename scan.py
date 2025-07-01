import requests
from dotenv import load_dotenv
import os
import time
import sqlalchemy as db

# Load environment variables for API-KEY
load_dotenv()
api_key = os.environ.get('API_KEY')

url = "https://www.virustotal.com/api/v3/urls"
headers = {
    "accept": "application/json",
    "x-apikey": api_key
}

# Set up sql database to store scan results
#engine = db.create_engine('sqlite:///scan_results.db')

def get_analysis_url():     
    # Prompt user for url to scan
    
    url = "https://www.virustotal.com/api/v3/urls"
    domain = input("Paste url to scan: ")

    payload = {"url": domain}

    # Call post request to obtain analysis ID for the url
    response = requests.post(url, data=payload, headers=headers)
    print(response.status_code)
    analysis_url = response.json()["data"]["links"]["self"]
    return analysis_url

def get_analysis_stats(url):
    analysis_response = requests.get(url, headers=headers)
    analysis_stats = analysis_response.json()["data"]["attributes"]["stats"]
    return analysis_stats

def main():
    analysis_url = get_analysis_url()
    time.sleep(30)
    print(get_analysis_stats(analysis_url))

if __name__=="__main__":
    main()    
