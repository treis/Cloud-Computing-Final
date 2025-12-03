import json
import logging
import pyodbc
import azure.functions as func
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from datetime import datetime
from typing import Callable
from opencensus.ext.azure.log_exporter import AzureLogHandler
import datetime

# -----------------------------
# App Setup
# -----------------------------
app = func.FunctionApp()

# -----------------------------
# Logging Setup (ILogger style)
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Application Insights Instrumentation Key
INSTRUMENTATION_KEY = "36adb2b6-03cf-47e8-b7e8-e55b28bec479"  # Replace with your key
azure_handler = AzureLogHandler(connection_string=f'InstrumentationKey={INSTRUMENTATION_KEY}')
logger.addHandler(azure_handler)

# -----------------------------
# Event System
# -----------------------------
class ValidationTriggeredEvent:
    def __init__(self, item_id, problems):
        self.item_id = item_id
        self.problems = problems
        self.timestamp = datetime.utcnow()

class ItemDeletedEvent:
    def __init__(self, item_id, name=None):
        self.item_id = item_id
        self.name = name
        self.timestamp = datetime.utcnow()

class EventDispatcher:
    def __init__(self):
        self._subscribers = {}

    def subscribe(self, event_type, callback: Callable):
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    def dispatch(self, event):
        for callback in self._subscribers.get(type(event), []):
            callback(event)

dispatcher = EventDispatcher()

# -----------------------------
# Event Handlers (log to App Insights)
# -----------------------------
def log_validation_event(event: ValidationTriggeredEvent):
    logger.info(
        "[EVENT] ValidationTriggered",
        extra={
            "custom_dimensions": {
                "event_type": "ValidationTriggered",
                "item_id": event.item_id,
                "problems": event.problems,
                "timestamp": str(event.timestamp)
            }
        }
    )

def log_item_deleted_event(event: ItemDeletedEvent):
    logger.info(
        "[EVENT] ItemDeleted",
        extra={
            "custom_dimensions": {
                "event_type": "ItemDeleted",
                "item_id": event.item_id,
                "name": event.name,
                "timestamp": str(event.timestamp)
            }
        }
    )

dispatcher.subscribe(ValidationTriggeredEvent, log_validation_event)
dispatcher.subscribe(ItemDeletedEvent, log_item_deleted_event)

# -----------------------------
# Key Vault Helper
# -----------------------------
def get_kv_api_key():
    vault_url = "https://ccfinalreiskeyvault.vault.azure.net/"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    return client.get_secret("apikey").value

# -----------------------------
# Request Verification
# -----------------------------
def verify_authority(req: func.HttpRequest) -> bool:
    provided_key = req.headers.get("api_key")
    valid_api_key = get_kv_api_key()
    return provided_key == valid_api_key

# -----------------------------
# JSON Response Helper
# -----------------------------
def json_response(payload: dict, status=200):
    return func.HttpResponse(
        json.dumps(payload),
        status_code=status,
        mimetype="application/json"
    )

# -----------------------------
# SQL Connection
# -----------------------------
def get_connection():
    try:
        conn_str = (
            "Driver={ODBC Driver 18 for SQL Server};"
            "Server=tcp:ccfinalreistazuredb.database.windows.net,1433;"
            "Database=product;"
            "Authentication=ActiveDirectoryMsi;"
            "Encrypt=yes;"
            "TrustServerCertificate=no;"
            "Connection Timeout=30;"
        )
        conn = pyodbc.connect(conn_str)
        logger.info("[SQL] Connection established successfully")
        return conn
    except pyodbc.Error:
        logger.exception("[SQL] Connection failed")
        raise

def ensure_table_exists(cursor):
    cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='products' AND xtype='U')
        CREATE TABLE products (
            id INT IDENTITY(1,1) PRIMARY KEY,
            name NVARCHAR(100) NOT NULL,
            price DECIMAL(10,2) NOT NULL
        )
    """)
    cursor.commit()

# -----------------------------
# CREATE Endpoint
# -----------------------------
@app.function_name("create_item")
@app.route(route="product/create", auth_level=func.AuthLevel.ANONYMOUS)
def create_item(req: func.HttpRequest) -> func.HttpResponse:
    logger.info("[CREATE] Request received")
    if not verify_authority(req):
        logger.warning("[CREATE] Unauthorized access attempt")
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        body = req.get_json()
    except ValueError:
        logger.warning("[CREATE] Invalid JSON body")
        return json_response({"error": "Invalid JSON body"}, 400)

    name = body.get("name")
    price = body.get("price")

    if not name or price is None:
        logger.warning("[CREATE] Missing required fields")
        return json_response({"error": "Missing required fields"}, 400)

    try:
        conn = get_connection()
        cursor = conn.cursor()
        ensure_table_exists(cursor)
        cursor.execute("INSERT INTO products (name, price) VALUES (?, ?)", (name, price))
        conn.commit()
        logger.info("[CREATE] Item created successfully: %s, %s", name, price)
    except Exception as e:
        logger.exception("[CREATE] Failed to create item")
        return json_response({"error": str(e)}, 500)

    return json_response({"message": "Item created", "name": name, "price": price}, 201)

# -----------------------------
# UPDATE Endpoint
# -----------------------------
@app.function_name("update_item")
@app.route(route="product/update", auth_level=func.AuthLevel.ANONYMOUS)
def update_item(req: func.HttpRequest) -> func.HttpResponse:
    logger.info("[UPDATE] Request received")
    if not verify_authority(req):
        logger.warning("[UPDATE] Unauthorized access attempt")
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        body = req.get_json()
    except ValueError:
        logger.warning("[UPDATE] Invalid JSON body")
        return json_response({"error": "Invalid JSON"}, 400)

    item_id = body.get("id")
    name = body.get("name")
    price = body.get("price")

    if not item_id or not name or price is None:
        logger.warning("[UPDATE] Missing required fields")
        return json_response({"error": "Missing required fields"}, 400)

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE products SET name = ?, price = ? WHERE id = ?", (name, price, item_id))
        conn.commit()
        logger.info("[UPDATE] Item updated: %s, %s, %s", item_id, name, price)
    except pyodbc.Error as e:
        logger.exception("[UPDATE] SQL error")
        return json_response({"error": str(e)}, 400)

    return json_response({"message": "Item updated", "id": item_id, "name": name, "price": price}, 200)

# -----------------------------
# DELETE Endpoint
# -----------------------------
@app.function_name("delete_item")
@app.route(route="product/delete", auth_level=func.AuthLevel.ANONYMOUS)
def delete_item(req: func.HttpRequest) -> func.HttpResponse:
    logger.info("[DELETE] Request received")
    if not verify_authority(req):
        logger.warning("[DELETE] Unauthorized access attempt")
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        body = req.get_json()
    except ValueError:
        logger.warning("[DELETE] Invalid JSON body")
        return json_response({"error": "Invalid JSON"}, 400)

    item_id = body.get("id")
    if not item_id:
        logger.warning("[DELETE] Missing id")
        return json_response({"error": "Missing id"}, 400)

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM products WHERE id = ?", (item_id,))
        conn.commit()
        logger.info("[DELETE] Item deleted: %s", item_id)
        dispatcher.dispatch(ItemDeletedEvent(item_id))
    except pyodbc.Error as e:
        logger.exception("[DELETE] SQL error")
        return json_response({"error": str(e)}, 400)

    return json_response({"message": "Item deleted", "id": item_id}, 200)

# -----------------------------
# READ Endpoint
# -----------------------------
@app.function_name("read_item")
@app.route(route="product/read", auth_level=func.AuthLevel.ANONYMOUS)
def read_item(req: func.HttpRequest) -> func.HttpResponse:
    logger.info("[READ] Request received")
    if not verify_authority(req):
        logger.warning("[READ] Unauthorized access attempt")
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, price FROM products ORDER BY id")
        rows = cursor.fetchall()
        items = [{"id": r[0], "name": r[1], "price": float(r[2])} for r in rows]
        logger.info("[READ] Retrieved %s items", len(items))
    except pyodbc.Error as e:
        logger.exception("[READ] SQL error")
        return json_response({"error": str(e)}, 400)

    return json_response({"items": items}, 200)

# -----------------------------
# VERIFY Endpoint
# -----------------------------
@app.function_name("verify_items")
@app.route(route="product/verify", auth_level=func.AuthLevel.ANONYMOUS)
def verify_items(req: func.HttpRequest) -> func.HttpResponse:
    logger.info("[VERIFY] Request received")
    if not verify_authority(req):
        logger.warning("[VERIFY] Unauthorized access attempt")
        return json_response({"error": "Unauthorized access"}, 401)

    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, price FROM products ORDER BY id")
        rows = cursor.fetchall()
    except pyodbc.Error as e:
        logger.exception("[VERIFY] SQL error")
        return json_response({"error": str(e)}, 400)

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
            dispatcher.dispatch(ValidationTriggeredEvent(r[0], row_issues))

    logger.info("[VERIFY] Validation complete: all_valid=%s, total_items=%s", all_valid, len(rows))
    return json_response({
        "all_items_valid": all_valid,
        "total_items": len(rows),
        "issues": issues,
        "time": datetime.datetime.now()
    }, 200)
