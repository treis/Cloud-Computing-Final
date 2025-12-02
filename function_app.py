import os
import json
import logging
import pyodbc
import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

# Set up function app
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Setup Azure SQL Server connection
db_connection_string = os.getenv("AZURE_SQL_CONNECTIONSTRING")
conn = pyodbc.connect(db_connection_string)
cursor = conn.cursor()

# Setup Key Vault client to retrieve API key
vault_url = "https://ccfinalkeyvault.vault.azure.net/"
credential = DefaultAzureCredential()
client = SecretClient(vault_url=vault_url, credential=credential)
valid_api_key = client.get_secret("ApiKey").value

# Ensure products table exists
cursor.execute('''
    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='products' AND xtype='U')
    CREATE TABLE products (
        id INT IDENTITY(1,1) PRIMARY KEY,
        name NVARCHAR(100) NOT NULL,
        price DECIMAL(10, 2) NOT NULL
    );
''')
conn.commit()




def verify_authority(key: str) -> bool:
    return key == valid_api_key

def has_body(request: func.HttpRequest) -> bool:
    try:
        request.get_json()
        return True
    except ValueError:
        return False

def prepare_data(rows):
    output = []
    for row in rows:
        output.append({
            "id": row[0],
            "name": row[1],
            "price": row[2]
        })
    return output

def json_response(payload: dict, status_code: int):
    return func.HttpResponse(
        json.dumps(payload),
        status_code=status_code,
        mimetype="application/json"
    )



@app.route(route="api/product/create")
def create_item(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[CREATE] Request received")

    provided_key = req.headers.get('api_key')
    if not verify_authority(provided_key):
        logging.warning("[CREATE] Unauthorized request")
        return json_response({"error": "Unauthorized access"}, 401)

    if not has_body(req):
        logging.warning("[CREATE] Missing JSON body")
        return json_response({"error": "Bad request"}, 400)

    body = req.get_json()
    name = body.get("name")
    price = body.get("price")

    if name and price:
        cursor.execute("INSERT INTO products (name, price) VALUES (?, ?)", (name, price))
        conn.commit()

        logging.info(f"[CREATE] Insert success: {name}, {price}")
        return json_response({"message": "Item created", "name": name, "price": price}, 201)

    logging.warning("[CREATE] Missing required fields")
    return json_response({"error": "Bad request"}, 400)



@app.route(route="api/product/update")
def update_item(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[UPDATE] Request received")

    provided_key = req.headers.get("api_key")
    if not verify_authority(provided_key):
        logging.warning("[UPDATE] Unauthorized request")
        return json_response({"error": "Unauthorized access"}, 401)

    if not has_body(req):
        logging.warning("[UPDATE] Missing JSON body")
        return json_response({"error": "Bad request"}, 400)

    body = req.get_json()
    name = body.get("name")
    price = body.get("price")
    provided_id = body.get("id")

    if name and price and provided_id:
        try:
            cursor.execute("""
                UPDATE products
                SET name = ?, price = ?
                WHERE id = ?
            """, (name, price, provided_id))
            conn.commit()

            logging.info(f"[UPDATE] Updated ID {provided_id} -> {name}, {price}")
            return json_response({
                "message": "Item updated",
                "id": provided_id,
                "name": name,
                "price": price
            }, 200)

        except pyodbc.Error as e:
            logging.error(f"[UPDATE] SQL Error: {e}")
            return json_response({"error": str(e)}, 400)

    logging.warning("[UPDATE] Missing required fields")
    return json_response({"error": "Bad request"}, 400)


@app.route(route="api/product/delete")
def delete_item(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[DELETE] Request received")

    provided_key = req.headers.get("api_key")
    if not verify_authority(provided_key):
        logging.warning("[DELETE] Unauthorized request")
        return json_response({"error": "Unauthorized access"}, 401)

    if not has_body(req):
        logging.warning("[DELETE] Missing JSON body")
        return json_response({"error": "Bad request"}, 400)

    body = req.get_json()
    provided_id = body.get("id")

    if provided_id:
        try:
            cursor.execute("DELETE FROM products WHERE id = ?", (provided_id,))
            conn.commit()

            logging.info(f"[DELETE] Deleted ID {provided_id}")
            return json_response({"message": "Item deleted", "id": provided_id}, 200)

        except pyodbc.Error as e:
            logging.error(f"[DELETE] SQL Error: {e}")
            return json_response({"error": str(e)}, 400)

    logging.warning("[DELETE] Missing required ID")
    return json_response({"error": "Bad request"}, 400)


@app.route(route="api/product/read")
def read_item(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[READ] Request received")

    provided_key = req.headers.get("api_key")
    if not verify_authority(provided_key):
        logging.warning("[READ] Unauthorized request")
        return json_response({"error": "Unauthorized access"}, 401)

    cursor.execute("SELECT * FROM products ORDER BY id")
    rows = cursor.fetchall()
    output = prepare_data(rows)

    logging.info(f"[READ] Returning {len(output)} items")
    return json_response({"items": output}, 200)


@app.route(route="api/product/verify")
def verify_items(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[VERIFY] Validation scan triggered")

    provided_key = req.headers.get("api_key")
    if not verify_authority(provided_key):
        logging.warning("[VERIFY] Unauthorized request")
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        cursor.execute("SELECT id, name, price FROM products ORDER BY id")
        rows = cursor.fetchall()

        issues = []
        all_valid = True

        for row in rows:
            row_issues = {}

            if row[0] is None:
                row_issues["id"] = "Missing"
            if not row[1]:
                row_issues["name"] = "Missing or empty"
            if row[2] is None:
                row_issues["price"] = "Missing"

            if row_issues:
                all_valid = False
                issues.append({
                    "id": row[0],
                    "problems": row_issues
                })

        logging.info(f"[VERIFY] Total items: {len(rows)} | Issues: {len(issues)}")

        return json_response({
            "all_items_valid": all_valid,
            "total_items": len(rows),
            "issues": issues
        }, 200)

    except pyodbc.Error as e:
        logging.error(f"[VERIFY] SQL Error: {e}")
        return json_response({"error": str(e)}, 400)
