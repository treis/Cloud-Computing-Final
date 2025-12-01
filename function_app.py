import os
from dotenv import load_dotenv

load_dotenv() # load environment variable that has connection string to SQL server

import azure.functions as func
import logging

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
client = SecretClient(vault_url=os.getenv("VAULT_URL"), credential=credential)

# Fetch the secret
retrieved_secret = client.get_secret("apikey")  # Name of the secret in Key Vault
api_key = retrieved_secret.value

# Set up azure server enviroment and make the necessary singular SQL table that will be needed to do CRUD operations

import pyodbc

try: 
    db_connection_string = os.getenv("AZURE_SQL_CONNECTIONSTRING")
    conn = pyodbc.connect(db_connection_string)
except Exception as e: 
    print(f"Error: {str(e)}")

cursor = conn.cursor()

create_table_query = """
    CREATE TABLE Products (
        ProductID INT PRIMARY KEY IDENTITY(1,1),  -- Auto-increment primary key
        ProductName NVARCHAR(100) NOT NULL,         -- Product name (can't be NULL)
        Category NVARCHAR(50),                     -- Category of the product
        Price DECIMAL(10, 2),                      -- Price of the product with two decimal places
        StockQuantity INT,                         -- Quantity of product in stock
        DateAdded DATETIME DEFAULT GETDATE()       -- Date when the product was added (defaults to current date)
    );

    """
cursor.execute(create_table_query)

# Helper for authorizing CRUD operations

def authorization(api_key_attempt):
    if api_key_attempt == retrieved_secret: 
        return True
    else: 
        return False

@app.route(route="http_trigger")
def http_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
            status_code=200
        )
    
@app.route(route="check_access")
def check_access(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    api_key_attempt = req.params.get('apikey')

    if not authorization(api_key_attempt=api_key_attempt):
        return func.HttpResponse(
             "User not authorized.",
             status_code=401
        )

    else:
        return func.HttpResponse(f"Hello, this HTTP triggered function executed successfully. You are authorized.")