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
    if analysis_breaches.status_code == 200:
        breaches_stats = analysis_breaches.json()
        return breaches_stats
    else:
        return []

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
    
    if len(breaches) == 0:
        print("There Have been no breaches in that email")
        return

    with engine.connect() as connection:
        for breach in breaches:
            stmt = insert(breaches_table).values(
                email=email,
                breach=breach['Name'],
                date=breach['BreachDate'],
                fixed='false'
            )

            try:
                connection.execute(stmt)
            except IntegrityError:
                pass
        connection.commit()

    with engine.connect() as connection:
        result = connection.execute(db.text(
        "SELECT breach, date FROM breaches WHERE email = :email AND fixed = 'false' ORDER BY date DESC"
        ), {'email': email}).fetchall()

        breach_date_list = [(row[0], row[1]) for row in result]
        for breach_date in breach_date_list:
            print(f"Breach: {breach_date[0]}\nDate: {breach_date[1]}\n")


def update_data_vase():
    pass


def main():
    # analysis_url = get_analysis_url()
    # time.sleep(5)
    # print(get_analysis_stats(analysis_url))
    # print("\n")
    data_base()

if __name__=="__main__":
    main() 
