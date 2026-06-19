# Inventory Management System

A small Flask + SQLite web application for tracking incoming material, outgoing/used material, live stock balance, serial numbers, rack locations, warranty details, and reports.

## Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

Default login:

- Login ID: `TannyFlux`
- Password: `Admin@123`

For access from phones or other PCs on the same Wi-Fi/LAN, run the app and open:

`http://YOUR-PC-IP-ADDRESS:5000`

Example: `http://192.168.1.25:5000`

Use the admin `Users` page to create more login IDs.
Use `Change Password` after first login to replace the default admin password.

The SQLite database is created automatically at `instance/inventory.db`.
