import os, asyncio, json, ssl, asyncpg
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, HTTPException
from kafka import KafkaConsumer
from dotenv import load_dotenv

# Configure: use environment variables for connection security parameters
load_dotenv()
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "osquery_logs")
KAFKA_CA_FILE = os.getenv("KAFKA_CA_FILE")
KAFKA_CERT_FILE = os.getenv("KAFKA_CERT_FILE")
KAFKA_KEY_FILE = os.getenv("KAFKA_KEY_FILE")

# This should be your Supabase connection string (e.g., postgresql://user:pass@host:port/db)
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL", "postgresql://user:password@localhost:5432/postgres")
# Certificate authority file for secure PostgreSQL connection (often needed for cloud databases)
SUPABASE_CA_FILE = os.getenv("SUPABASE_CA_FILE")
SUPABASE_TABLE_NAME = "host_telemetry"

# Supabase/PostgreSQL Connection Pool 
db_pool: asyncpg.Pool | None = None

# Kafka Consumer & Supabase Write Logic
async def consume_kafka_messages():    
    # Configure Kafka TLS/SSL 
    kafka_consumer_args = {
        'bootstrap_servers': KAFKA_BROKER,
        'value_deserializer': lambda v: json.loads(v.decode('utf-8')),
        'auto_offset_reset': 'latest',
        'enable_auto_commit': True,
        'group_id': 'fastapi-supabase-consumer',
    }
    
    # If environment variables are set, add SSL parameters
    if KAFKA_CA_FILE and KAFKA_CERT_FILE and KAFKA_KEY_FILE:
        kafka_consumer_args.update({
            'security_protocol': 'SSL',
            'ssl_context': ssl.create_default_context(cafile=KAFKA_CA_FILE),
            'ssl_check_hostname': False, # Set to True in production if possible
            'ssl_certfile': KAFKA_CERT_FILE,
            'ssl_keyfile': KAFKA_KEY_FILE,
        })
    consumer = KafkaConsumer(KAFKA_TOPIC, **kafka_consumer_args)
    print("Starting Kafka consumer...")

    if not db_pool:
        print("Database connection pool not initialized. Cannot save data.")
        return

    async with db_pool.acquire() as connection:
        try:
            await connection.execute(f"SELECT 1 FROM {SUPABASE_TABLE_NAME} LIMIT 1")
        except asyncpg.exceptions.UndefinedTableError:
            print(f"Warning: Table {SUPABASE_TABLE_NAME} does not exist. Please create it.")
            return

    for message in consumer:
        try:
            osquery_log_entry = message.value
            osquery_log_entry['timestamp_processed'] = datetime.utcnow()
            data_json = json.dumps(osquery_log_entry)
            async with db_pool.acquire() as connection:
                await connection.execute(
                    f"""
                    INSERT INTO {SUPABASE_TABLE_NAME} (payload)
                    VALUES ($1)
                    """,
                    data_json
                )
            print(f"Successfully saved document from host: {osquery_log_entry.get('hostIdentifier')}")
        except Exception as e:
            print(f"Error processing or saving message to Supabase: {e}")

# Manage FastAPI App Lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool
    print("Connecting to Supabase (PostgreSQL)...")

    # Configure Supabase/PostgreSQL TLS/SSL 
    connect_args = {}
    if SUPABASE_CA_FILE:
        connect_args['ssl'] = ssl.create_default_context(cafile=SUPABASE_CA_FILE)
        
    # Initialize connection pool
    db_pool = await asyncpg.create_pool(
        SUPABASE_DB_URL,
        min_size=1, 
        max_size=10,
        **connect_args
    )
    print("Supabase connection established.")
    
    # Kafka consumer starts as background task
    task = asyncio.create_task(consume_kafka_messages())
    yield
    
    # Shutdown cleans up resources
    print("Closing Supabase connection pool...")
    await db_pool.close()
    print("Supabase connection closed.")
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        print("Kafka consumer task cancelled.")

# Initialize FastAPI 
app = FastAPI(lifespan=lifespan)

# API endpoints 
@app.get("/telemetry")
async def get_all_telemetry():
    """Retrieves the latest telemetry data from Supabase (PostgreSQL)."""
    if not db_pool:
        raise HTTPException(status_code=503, detail="Database connection not available.")
    
    async with db_pool.acquire() as connection:
        results = await connection.fetch(
            f"""
            SELECT * FROM {SUPABASE_TABLE_NAME}
            ORDER BY timestamp_processed DESC
            LIMIT 100
            """
        )
    
    data = [dict(record) for record in results]
    return {"telemetry_data": data}

@app.get("/telemetry/count")
async def get_telemetry_count():
    if not db_pool:
        raise HTTPException(status_code=503, detail="Database connection not available.")
    
    async with db_pool.acquire() as connection:
        count = await connection.fetchval(
            f"""
            SELECT COUNT(*) FROM {SUPABASE_TABLE_NAME}
            """
        )
    return {"count": count}
