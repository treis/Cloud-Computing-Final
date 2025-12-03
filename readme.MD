# Introduction
This API manages product inventory items using a serverless cloud-native architecture.  
Stable builds appear under tagged releases; the `main` branch may change frequently.

---

# Prerequisites

### Development Environment
- **Python 3.12**
- **Azure Account**
- **Azure CLI**
- **Azure Functions Core Tools v4**
- **Visual Studio Code** (recommended)

### Dependencies
- Python packages from `requirements.txt`
- Azure Tools extension pack (VS Code)
- Azure SQL extension (optional)

### Recommended Testing Tool
- Thunder Client

---

# Setup

Ensure all dependencies are installed before beginning.

---

# Python Environment Setup

This project is built with **Python 3.12x** and **Azure Functions**.

### 1. Create a Virtual Environment
```bash
python -m venv .venv
```

### 2. Activate the Environment
**Windows**
```bash
.venv\Scripts\activate
```

**macOS/Linux**
```bash
source .venv/bin/activate
```

### 3. Install Requirements
```bash
pip install -r requirements.txt
```

### 4. Install Azure Functions Core Tools
```bash
npm install -g azure-functions-core-tools@4 --unsafe-perm true
```

### 5. Login to Azure
```bash
az login
```

### 6. Run the API Locally
```bash
func start
```

---

# Database Setup (Azure SQL)

Requires Azure Portal access.

### 1. In your resource group, create:
- Azure SQL Server  
- Azure SQL Database named **product**

### 2. Set Yourself as Entra Administrator
Needed to run initial SQL commands.

### 3. Enable System Assigned Identity on the Function App

### 4. Grant SQL Permissions to the Function App
Open **Query Editor** and run:

```sql
CREATE USER [YOUR_FUNCTION_APP_NAME] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [YOUR_FUNCTION_APP_NAME];
ALTER ROLE db_datawriter ADD MEMBER [YOUR_FUNCTION_APP_NAME];
```

### 5. Networking Requirement for SQL
Enable:
**Allow Azure services and resources to access this server**

---

# Key Vault Setup

### 1. Create a Key Vault
In the same resource group as the Function App.

### 2. Add Secrets
- `apikey` → any string  
- (Database string is retrieved using Managed Identity, not stored here)

### 3. Assign Key Vault Access to Function App
Add role:
- **Key Vault Secrets User**

---

# Deployment

### 1. From VS Code → Azure Functions panel → Deploy to Function App  
### 2. Select your existing Function App  
### 3. Upload completes automatically  

Your API is now live at:

```
https://<your-function>.azurewebsites.net/api/
```

---

# Using the Product API

## Base URL
```
https://<yourapp>.azurewebsites.net/api/
```

## Authentication
Every request requires:
```
api_key: YOUR_API_KEY
```

---

# Product Object
```json
{
  "id": 1,
  "name": "Product Name",
  "price": 49.99
}
```

---

# Endpoints

---

## Create Item
### POST `/product/create`

**Headers**
```
api_key: KEY
```

**Body**
```json
{
  "name": "Keyboard",
  "price": 29.99
}
```

**Response (201)**
```json
{
  "message": "Item created",
  "name": "Keyboard",
  "price": 29.99
}
```

---

## Read Items
### GET `/product/read`

**Headers**
```
api_key: KEY
```

**Response (200)**
```json
{
  "items": [
    { "id": 1, "name": "Keyboard", "price": 29.99 }
  ]
}
```

---

## Update Item
### POST `/product/update`

**Headers**
```
api_key: KEY
```

**Body**
```json
{
  "id": 1,
  "name": "NewName",
  "price": 59.99
}
```

**Response (200)**
```json
{
  "message": "Item updated",
  "id": 1,
  "name": "NewName",
  "price": 59.99
}
```

---

## Delete Item
### POST `/product/delete`

**Headers**
```
api_key: KEY
```

**Body**
```json
{
  "id": 1
}
```

**Response (200)**
```json
{
  "message": "Item deleted",
  "id": 1
}
```

---

## Verify Items
### POST `/product/verify`

**Headers**
```
api_key: KEY
```

**Response (200)**
```json
{
  "all_items_valid": true,
  "total_items": 5,
  "issues": []
}
```

---

# Possible Errors

| Code | Message                                         |
|------|-------------------------------------------------|
| 401  | Unauthorized (invalid API key)                 |
| 400  | Missing required fields                        |
| 500  | Internal validation error                      |
