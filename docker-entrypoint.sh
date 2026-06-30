#!/bin/sh
set -e
python db/create_tables.py
exec python app.py
