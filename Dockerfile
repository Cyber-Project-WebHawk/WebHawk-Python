FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Use sh -c so Windows CRLF on the entrypoint script cannot break startup.
ENTRYPOINT ["sh", "-c", "python db/create_tables.py && exec python app.py"]
