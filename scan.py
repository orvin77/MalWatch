import requests
from dotenv import load_dotenv
import os
import time
import sqlalchemy as db
import pandas as pd
from sqlalchemy import Table, Column, String, MetaData, insert
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

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

def get_Pwned(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        "HIBP-API-KEY": os.environ.get('HIBP_API_KEY')
    }
    analysis_breaches = requests.get(url, headers=headers)
    breaches_stats = analysis_breaches.json()
    return breaches_stats

def data_base():
    email = input("Enter email to check breaches: ")

    engine = db.create_engine('sqlite:///data_base_name.db')
    metadata = MetaData()

    breaches_table = Table('breaches',metadata,
                         Column('email',String),
                         Column('breach', String),
                         Column('date', String),
                         Column('fixed', String),
                         db.PrimaryKeyConstraint('email', 'breach')
                         )
    
    metadata.create_all(engine)

    breaches = get_Pwned(email)

    with engine.connect() as connection:
        for breach in breaches:
            stmt = insert(breaches_table).values(
                email=email,
                breach=breach['Name'],
                date=breach['BreachDate'],
                fixed='true'
            )

            try:
                connection.execute(stmt)
            except IntegrityError:
                print("Already in data base")
                pass
        connection.commit()

        result = connection.execute(db.text("SELECT * FROM breaches")).fetchall()
        for row in result:
            print(row)

def main():
    analysis_url = get_analysis_url()
    time.sleep(5)
    print(get_analysis_stats(analysis_url))
    print("\n")
    data_base()

if __name__=="__main__":
    main() 
