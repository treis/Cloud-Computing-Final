import os
import json
import logging
import pyodbc
import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

# Set up function app variable
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Setup Azure SQL Server connection
db_connection_string = os.getenv("AZURE_SQL_CONNECTIONSTRING")
conn = pyodbc.connect(db_connection_string)
cursor = conn.cursor()

# Setup Azure Key Vault to retrieve the API Key
vault_url = "https://ccfinalkeyvault.vault.azure.net/"
credential = DefaultAzureCredential()
client = SecretClient(vault_url=vault_url, credential=credential)
valid_api_key = client.get_secret("ApiKey").value  # Fetch the secret value

# Create table if it does not exist in the SQL Server database
cursor.execute('''
    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='products' AND xtype='U')
    CREATE TABLE products (
        id INT IDENTITY(1,1) PRIMARY KEY,
        name NVARCHAR(100) NOT NULL,
        price DECIMAL(10, 2) NOT NULL
    );
''')
conn.commit()

# Helper functions
def verify_authority(key: str) -> bool:
    """Verify if the provided API key matches the stored API key"""
    return key == valid_api_key

def has_body(request: func.HttpRequest) -> bool:
    """Check if the request has a valid JSON body"""
    try:
        request.get_json()
        return True
    except ValueError:
        return False

def prepare_data(provided_data: list):
    """Prepare the result data for JSON response"""
    master_list = []
    for item_tuple in provided_data:
        id = item_tuple[0]
        name = item_tuple[1]
        price = item_tuple[2]
        master_list.append({'id': id, 'name': name, 'price': price})
    return master_list

def json_response(payload: dict, status_code: int):
    """Format the response as JSON"""
    return func.HttpResponse(
        json.dumps(payload),
        status_code=status_code,
        mimetype="application/json"
    )

# CREATE
@app.route(route="api/product/create")
def create_item(req: func.HttpRequest) -> func.HttpResponse:
    provided_key = req.headers.get('api_key')
    if not verify_authority(provided_key):
        return json_response({"error": "Unauthorized access"}, 401)
    
    if not has_body(req):
        return json_response({"error": "Bad request"}, 400)
    
    req_body = req.get_json()
    name = req_body.get('name')
    price = req_body.get('price')

    if name and price:
        cursor.execute("INSERT INTO products (name, price) VALUES (?, ?)", (name, price))
        conn.commit()
        logging.info(f"CREATE request successful. Item added to database.")
        return json_response({
            "message": "Item created",
            "id": new_id,
            "name": name,
            "price": price
        }, 201)
    else:
        return json_response({"error": "Bad request"}, 400)

# UPDATE
@app.route(route="api/product/update")
def update_item(req: func.HttpRequest) -> func.HttpResponse:
    provided_key = req.headers.get('api_key')
    if not verify_authority(provided_key):
        return json_response({"error": "Unauthorized access"}, 401)
    
    if not has_body(req):
        return json_response({"error": "Bad request"}, 400)

    req_body = req.get_json()
    name = req_body.get('name')
    price = req_body.get('price')
    provided_id = req_body.get('id')

    if name and price and provided_id:
        try:
            cursor.execute('''
                UPDATE products
                SET name = ?, price = ?
                WHERE id = ?
            ''', (name, price, provided_id))
            conn.commit()
            return json_response({
                "message": "Item updated",
                "id": provided_id,
                "name": name,
                "price": price
            }, 200)
        except pyodbc.Error as e:
            return json_response({"error": str(e)}, 400)
    else:
        return json_response({"error": "Bad request"}, 400)

# DELETE
@app.route(route="api/product/delete")
def delete_item(req: func.HttpRequest) -> func.HttpResponse:
    provided_key = req.headers.get('api_key')
    if not verify_authority(provided_key):
        return json_response({"error": "Unauthorized access"}, 401)
    
    if not has_body(req):
        return json_response({"error": "Bad request"}, 400)

    req_body = req.get_json()
    provided_id = req_body.get('id')

    if provided_id:
        try:
            cursor.execute('DELETE FROM products WHERE id = ?', (provided_id,))
            conn.commit()
            return json_response({"message": "Item deleted", "id": provided_id}, 200)
        except pyodbc.Error as e:
            return json_response({"error": str(e)}, 400)
    else:
        return json_response({"error": "Bad request"}, 400)

# READ
@app.route(route="api/product/read")
def read_item(req: func.HttpRequest) -> func.HttpResponse:
    provided_key = req.headers.get('api_key')
    if not verify_authority(provided_key):
        return json_response({"error": "Unauthorized access"}, 401)
    
    cursor.execute("SELECT * FROM products ORDER BY id")
    unprocessed_data = cursor.fetchall()
    output = prepare_data(unprocessed_data)
    logging.info(f"Current list of items: {output}")
    return json_response({"items": output}, 200)

# VERIFY 

@app.route(route="api/product/verify")
def verify_items(req: func.HttpRequest) -> func.HttpResponse:
    provided_key = req.headers.get('api_key')
    if not verify_authority(provided_key):
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        cursor.execute("SELECT id, name, price FROM products ORDER BY id")
        rows = cursor.fetchall()

        all_valid = True
        issues = []

        for row in rows:
            record_issues = {}

            # Check each required field
            if row[0] is None:
                record_issues["id"] = "Missing"
            if row[1] is None or row[1] == "":
                record_issues["name"] = "Missing or empty"
            if row[2] is None:
                record_issues["price"] = "Missing"

            # If issues detected for this row, record them
            if record_issues:
                all_valid = False
                issues.append({
                    "id": row[0],
                    "problems": record_issues
                })

        return json_response({
            "all_items_valid": all_valid,
            "total_items": len(rows),
            "issues": issues
        }, 200)

    except pyodbc.Error as e:
        return json_response({"error": str(e)}, 400)
