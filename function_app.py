import os
import json
import logging
import pyodbc
import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

app = func.FunctionApp()

def get_kv_api_key():
    """
    Retrieves the API key from Azure Key Vault using a managed identity.
    """
    vault_url = "https://ccfinalkv.vault.azure.net/"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    return client.get_secret("apikey").value


def verify_authority(req: func.HttpRequest) -> bool:
    """
    Verifies the request's API key header against the Key Vault key.
    """
    provided_key = req.headers.get("api_key")
    valid_api_key = get_kv_api_key()
    return provided_key == valid_api_key


def json_response(payload: dict, status=200):
    """
    Standard JSON HTTP response.
    """
    return func.HttpResponse(
        json.dumps(payload),
        status_code=status,
        mimetype="application/json"
    )

def get_connection():
    """
    Connects to Azure SQL Database using user-assigned Managed Identity.
    """

    try:
        conn_str = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:ccfinaldb.database.windows.net,1433;Database=product;Uid=2357738c-c9d0-427d-a24b-19a99e528541;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;Authentication=ActiveDirectoryIntegrated"
        return pyodbc.connect(conn_str)

    except pyodbc.Error as e:
        logging.error(f"SQL Connection failed: {e}")
        raise

def ensure_table_exists(cursor):
    """
    Ensures the 'products' table exists.
    """
    cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='products' AND xtype='U')
        CREATE TABLE products (
            id INT IDENTITY(1,1) PRIMARY KEY,
            name NVARCHAR(100) NOT NULL,
            price DECIMAL(10,2) NOT NULL
        )
    """)
    cursor.commit()

@app.function_name("create_product")
@app.route(route="api/product/create", auth_level=func.AuthLevel.ANONYMOUS)
def create_item(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[CREATE] Request received")

    if not verify_authority(req):
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        body = req.get_json()
    except ValueError:
        return json_response({"error": "Invalid JSON body"}, 400)

    name = body.get("name")
    price = body.get("price")

    if not name or price is None:
        return json_response({"error": "Missing required fields"}, 400)

    conn = get_connection()
    cursor = conn.cursor()
    ensure_table_exists(cursor)

    cursor.execute("INSERT INTO products (name, price) VALUES (?, ?)", (name, price))
    conn.commit()

    return json_response(
        {"message": "Item created", "name": name, "price": price},
        status=201
    )


@app.function_name("product_update")
@app.route(route="product/update", auth_level=func.AuthLevel.ANONYMOUS)
def update_item(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[UPDATE] Request received")

    if not verify_authority(req):
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        body = req.get_json()
    except ValueError:
        return json_response({"error": "Invalid JSON"}, 400)

    item_id = body.get("id")
    name = body.get("name")
    price = body.get("price")

    if not item_id or not name or price is None:
        return json_response({"error": "Missing required fields"}, 400)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "UPDATE products SET name = ?, price = ? WHERE id = ?",
            (name, price, item_id),
        )
        conn.commit()
    except pyodbc.Error as e:
        logging.error(f"[UPDATE] SQL ERROR: {e}")
        return json_response({"error": str(e)}, 400)

    return json_response(
        {"message": "Item updated", "id": item_id, "name": name, "price": price},
        200
    )


@app.function_name("product_delete")
@app.route(route="product/delete", auth_level=func.AuthLevel.ANONYMOUS)
def delete_item(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[DELETE] Request received")

    if not verify_authority(req):
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        body = req.get_json()
    except ValueError:
        return json_response({"error": "Invalid JSON"}, 400)

    item_id = body.get("id")

    if not item_id:
        return json_response({"error": "Missing id"}, 400)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM products WHERE id = ?", (item_id,))
        conn.commit()
    except pyodbc.Error as e:
        logging.error(f"[DELETE] SQL ERROR: {e}")
        return json_response({"error": str(e)}, 400)

    return json_response({"message": "Item deleted", "id": item_id}, 200)


@app.function_name("product_read")
@app.route(route="product/read", auth_level=func.AuthLevel.ANONYMOUS)
def read_item(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[READ] Request received")

    if not verify_authority(req):
        return json_response({"error": "Unauthorized access"}, 401)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, name, price FROM products ORDER BY id")
    rows = cursor.fetchall()

    items = [{"id": r[0], "name": r[1], "price": float(r[2])} for r in rows]

    return json_response({"items": items}, 200)


@app.function_name("product_verify")
@app.route(route="product/verify", auth_level=func.AuthLevel.ANONYMOUS)
def verify_items(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("[VERIFY] Request received")

    if not verify_authority(req):
        return json_response({"error": "Unauthorized access"}, 401)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, name, price FROM products ORDER BY id")
    rows = cursor.fetchall()

    issues = []
    all_valid = True

    for r in rows:
        row_issues = {}

        if r[0] is None:
            row_issues["id"] = "Missing ID"
        if not r[1]:
            row_issues["name"] = "Missing name"
        if r[2] is None:
            row_issues["price"] = "Missing price"

        if row_issues:
            all_valid = False
            issues.append({"id": r[0], "problems": row_issues})

    return json_response(
        {
            "all_items_valid": all_valid,
            "total_items": len(rows),
            "issues": issues
        },
        200
    )
