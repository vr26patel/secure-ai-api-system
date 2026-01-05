from fastapi import FastAPI, Header, HTTPException
import time
import logging

# -----------------------------
# Create FastAPI app
# -----------------------------
app = FastAPI()

# -----------------------------
# Logging configuration
# -----------------------------
logging.basicConfig(
    filename="api.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# -----------------------------
# Security configuration
# -----------------------------
API_KEY = "my-secret-key"

RATE_LIMIT = 5          # max requests
TIME_WINDOW = 60        # seconds

request_log = {}        # stores request times per API key
alert_counter = {}      # stores abuse count per API key
blocked_keys = set()    # temporarily blocked API keys

ALERT_THRESHOLD = 1     # alert after 1 abuse event

# -----------------------------
# API Endpoint
# -----------------------------
@app.get("/")
def home(x_api_key: str = Header(None)):

    # 1️⃣ Authentication
    if x_api_key != API_KEY:
        logging.warning("Unauthorized access attempt")
        raise HTTPException(status_code=401, detail="Unauthorized")

    # 2️⃣ Check if API key is blocked
    if x_api_key in blocked_keys:
        logging.critical("Blocked API key attempted access")
        raise HTTPException(status_code=403, detail="API key temporarily blocked")

    now = time.time()

    # 3️⃣ Get previous request times
    request_times = request_log.get(x_api_key, [])

    # 4️⃣ Remove old requests outside time window
    request_times = [t for t in request_times if now - t < TIME_WINDOW]

    # 5️⃣ Rate limit check
    if len(request_times) >= RATE_LIMIT:
        logging.warning("Rate limit exceeded for API key")

        count = alert_counter.get(x_api_key, 0) + 1
        alert_counter[x_api_key] = count

        logging.error("ALERT: Possible API abuse detected!")

        # Incident response: block key
        if count >= ALERT_THRESHOLD:
            blocked_keys.add(x_api_key)
            logging.critical("API key temporarily blocked due to abuse")

        raise HTTPException(status_code=429, detail="Too many requests")

    # 6️⃣ Log request
    request_times.append(now)
    request_log[x_api_key] = request_times

    logging.info("Request allowed")
    return {"message": "AI Security API is running"}
