# iplistd - README.md

Create  a virtual environment

apt install python3-pip python3-venv
python3 -m venv .venv
pip install -r requirements.txt

Edit: ~/.config/systemd/user
```
[Unit]
Description=ShunIP Uvicorn Service
After=network.target

[Service]
WorkingDirectory=/home/admin/work/iplistd
ExecStart=/home/admin/work/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

# Optional env vars
Environment="ENV=production" "PORT=8000"

[Install]
WantedBy=default.target
```

systemctl --user daemon-reload
systemctl --user enable myapp.service
systemctl --user start myapp.service

sudo loginctl enable-linger admin

## Example Usage with CURL

curl -X POST "http://localhost:8000/ip-filters/" \
     -H "Authorization: Bearer sk_admin_1234567890abcdef" \
     -H "Content-Type: application/json" \
     -d '{
       "ip_address": "203.0.113.45",
       "timeout_minutes": 30
     }'

## iplistc.py

Script to add IP to the ban list. Retrieves API key via vault.
