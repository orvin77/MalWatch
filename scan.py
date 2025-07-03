import os
import time
import requests
import pandas as pd
from dotenv import load_dotenv

import sqlalchemy as db
from sqlalchemy import Table, Column, String, MetaData, insert, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from google import genai
from google.genai import types

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

    # Extract analysis URL from response to get status information
    analysis_url = response.json()["data"]["links"]["self"]
    print(analysis_url)
    return analysis_url

# Function to get analysis statistics using analysis URL
def get_analysis_stats(url):
    analysis_response = requests.get(url, headers=headers)
    analysis_stats = analysis_response.json()["data"]["attributes"]["stats"]
    print(analysis_stats)
    return analysis_stats

# Function to get a more comprehensive analysis of the information using geminiAI
def get_summary(stats):
    ai_key = os.environ.get('GENAI_KEY')
    genai.api_key = ai_key
    # Create an genAI client using the key from our environment variable
    client = genai.Client(
        api_key=ai_key,
    )

    # Specify the model to use and the messages to send
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        config=types.GenerateContentConfig(
            system_instruction="You are knowledgable in website and domain security regarding malicious websites and you can explain the the stats of scanned URLs which includes a number/score for these sections in the stats: malicious, suspicious, undetected, harmless, and timeout."
        ),
        contents=f"Can you give a brief summary of the statistics for a scanned URL as well as any suggestions for the user, keep it short and simple, the user is not very tech savy. Here are the stats: {stats}?",
    )
    print(response.text)

# Function to set up a conection to SQLite database and fill it with breach information
def get_db():
    engine = db.create_engine('sqlite:///data_base_name.db')
    metadata = MetaData()

    # Defines the columns of the table
    breaches_table = Table('breaches',metadata,
                         Column('email',String),
                         Column('breach', String),
                         Column('date', String),
                         Column('fixed', String),
                         db.PrimaryKeyConstraint('email', 'breach')
                         )
    
    # creates table
    metadata.create_all(engine)
    return engine, breaches_table

# Function to check if the email has been breached
def get_pwned(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        "HIBP-API-KEY": os.environ.get('HIBP_API_KEY')
    }
    analysis_breaches = requests.get(url, headers=headers)
    if analysis_breaches.status_code == 200:
        breaches = analysis_breaches.json()
        return analysis_breaches.status_code, breaches
    else:
        return analysis_breaches.status_code, []

# Function to get suggestion on how to handle a breach using GgeminiAI 
def get_suggestions(breach_list):
    ai_key = os.environ.get('GENAI_KEY')
    genai.api_key = ai_key
    # Create an genAI client using the key from our environment variable
    client = genai.Client(
        api_key=ai_key,
    )

    # Specify the model to use and the messages to send
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        config=types.GenerateContentConfig(
            system_instruction="You are knowledgable in website and domain security regarding malicious websites and you can give the user suggestions on what to do regarding websites that have been breached that contains the user's email."
        ),
        contents=f"Can you give suggestions to the user based off this list of breached websites: {breach_list}? You could also suggest official data removal websites that help request your data to be removed. Keep it really short and simple, don't need to go too in depth, the user may not be too tech savy.",
    )
    print(response.text)

#Function that Inserts breach info to the database givin a certain email
def data_base(email):
    engine, breaches_table = get_db()
    
    status, breaches = get_pwned(email)

    if len(breaches) == 0:
        print("There Have been no breaches in that email")
        return []

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
            except IntegrityError: #Ignore duplicate entries
                pass
        connection.commit()

    with engine.connect() as connection:
        result = connection.execute(db.text(
        "SELECT breach, date FROM breaches WHERE email = :email AND fixed = 'false' ORDER BY date DESC"
        ), {'email': email}).fetchall()

        breach_date_list = [(row[0], row[1]) for row in result]
        return breach_date_list

# Function to update breach status to fixed in database
def update_data_base(email, breach_list):
    engine = db.create_engine('sqlite:///data_base_name.db')
    metadata = MetaData()
    metadata.reflect(bind=engine)

    breaches_table = metadata.tables['breaches']

    with engine.connect() as connection:
        for breach_name in breach_list:
            stmt = (
                update(breaches_table)
                .where(
                    breaches_table.c.email == email,
                    breaches_table.c.breach == breach_name
                )
                .values(fixed='true')
            )

            result = connection.execute(stmt)
            connection.commit()
    
    # Print cinfirmation of fixed breaches
    for i, breach_name in enumerate(breach_list):
        print(f"{i+1}. {breach_name}" )

    print("These breaches were fixed")


# Main Program/ Menu System 
def main():
    print("Welcome to Malwatch where we help you do better in your web safety")
    email = input("\nPlease input your email so we can get started: ")
    cont = True
    counter = 0
    while cont:
        print("\n-----MENU-----")
        print("1. leaked data")
        print("2. update data")
        print("3. suspicous urls")
        print("4. Exit ")

        ans = input("Enter an number between 1-4: ")

        if ans == '1':
            if counter>=1:
                change_email = input("Would you like to check a different email?(y/n): ")
                if change_email=='y' or change_email=='Y':
                    email = input("Enter new email to check: ")

            breached_list = data_base(email)
            for breach_date in breached_list:
                print(f"Breach: {breach_date[0]}\nDate: {breach_date[1]}\n")

            get_suggestions(breached_list)

        elif ans == '2':
            breached_list = data_base(email)
            if len(breached_list) == 0:
                print("There are no breaches to update\n")
                continue

            for ind, breach in enumerate(breached_list):
                print(f"{ind+1}. {breach[0]}")

            print("Enter the numbers of the breaches fixed seperated by a space "
            "or type 'all' if you fixed them all: ")

            fixed = input('\nEnter the numbers of the breaches fixed seperated by a space \n'
            'Type "all" if you fixed them all\n' \
            'Click "ENTER" to cancel:\n')
            fixed = fixed.split()

            breached = []

            if len(fixed) == 0:
                print("No Changes made")
                continue

            if fixed[0] == "all":
                for breach in breached_list:
                    breached.append(breach[0])
                update_data_base(email, breached)
            else:
                for i in fixed:
                    index = int(i)
                    breached.append(breached_list[index-1][0])
                update_data_base(email, breached)

        elif ans == '3':
            analysis_url = get_analysis_url()
            time.sleep(15)
            stats = get_analysis_stats(analysis_url)
            get_summary(stats)

        elif ans == '4':
            print("Thanks for using Malwatch come again any time")
            cont = False

        else:
            print("That is not a valid input")
        counter+=1

if __name__=="__main__":
    main() 
