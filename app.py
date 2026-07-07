####################################################
#--- Importation des modules ---
####################################################
import re
import html
import os
import hmac
import hashlib
import time
from urllib.parse import urlparse
import json
import requests
import logging
import telnyx
from telnyx import Telnyx
import boto3
import redis
from botocore.client import Config
from botocore.exceptions import ClientError, NoCredentialsError
from flask import Flask, request, Response
from werkzeug.utils import secure_filename
from dotenv import load_dotenv, find_dotenv
from celery import Celery

####################################################
#--- Fonction d'initialisation ---
####################################################

# --- Chargement des variables d'environnement (.env) ---
load_dotenv(find_dotenv(), override=False)

app = Flask(__name__)

# --- Initialisation de la base de donnes Redis ---
redis_client = redis.StrictRedis(host='localhost', port=6379, db=1)

def set_fax_file(fax_id, file_path):
    redis_client.set(fax_id, file_path)

def get_fax_file(fax_id):
    file_path = redis_client.get(fax_id)
    return file_path.decode() if file_path else None

def delete_fax_file(fax_id):
    redis_client.delete(fax_id)

def set_fax_meta(fax_id, meta_dict, ttl_seconds=7*24*3600):
    redis_client.set(f"fax_meta:{fax_id}", json.dumps(meta_dict), ex=ttl_seconds)

def get_fax_meta(fax_id):
    raw = redis_client.get(f"fax_meta:{fax_id}")
    return json.loads(raw.decode()) if raw else None

def delete_fax_meta(fax_id):
    redis_client.delete(f"fax_meta:{fax_id}")

def mark_fax_notified_once(fax_id, ttl_seconds=7*24*3600):
    """
    Returns True only the first time it's called for a fax_id.
    Prevents duplicate emails when Telnyx retries webhooks. [1](https://support.telnyx.com/en/articles/4394516-configuring-programmable-fax-applications)
    """
    key = f"fax_notified:{fax_id}"
    # SET key value NX EX ttl
    return bool(redis_client.set(key, "1", nx=True, ex=ttl_seconds))

# --- Initialisation du module Celery ---
celery = Celery(
    'app',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

# --- Initialisation de la base de données "In-Memory" ---

with open("db.json", "r") as f:
    DB = json.load(f)

# --- Initialisation du module de journlisation ---
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# --- Initialisation du repertoire de telechargement ---
DOWNLOAD_DIR = "/opt/telnyx/downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# --- Initialisation du module Telnyx ---
telnyx.api_key = os.getenv("TELNYX_API_KEY")
telnyx.public_key = os.getenv("TELNYX_PUBLIC_KEY")
client = Telnyx(api_key=telnyx.api_key)

# --- Initialisation du module Mailgun ---
MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY")
MAILGUN_DOMAIN = os.getenv("MAILGUN_DOMAIN")
MAILGUN_SIGNING_KEY = os.getenv("MAILGUN_SIGNING_KEY")

# Maximum age of a webhook timestamp before it is rejected (5 minutes)
MAX_TIMESTAMP_AGE = 300


def verify_mailgun_signature(timestamp, token, signature):
    """
    Verify the Mailgun webhook HMAC-SHA256 signature.
    Concatenate timestamp + token, sign with the Webhook Signing Key,
    and compare to the provided signature.
    Also rejects requests where the timestamp is more than MAX_TIMESTAMP_AGE
    seconds old to prevent replay attacks.
    """
    # Reject stale timestamps
    try:
        age = abs(time.time() - int(timestamp))
        if age > MAX_TIMESTAMP_AGE:
            logger.warning(f"Webhook timestamp too old: {age:.0f}s")
            return False
    except (ValueError, TypeError):
        logger.warning("Invalid webhook timestamp.")
        return False

    # Compute expected signature
    expected = hmac.new(
        MAILGUN_SIGNING_KEY.encode(),
        msg=f"{timestamp}{token}".encode(),
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        logger.warning("Mailgun signature verification failed.")
        return False

    logger.debug("Mailgun signature verified successfully.")
    return True

# --- Initialisation du module AWS S3 ---
_s3_client = None
def get_s3_client():
    global _s3_client
    if _s3_client is None:
        region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "ca-central-1"
        _s3_client = boto3.client(
            "s3",
            region_name=region,
            config=Config(signature_version='s3v4')
        )
    return _s3_client

def get_bucket_name() -> str:
    name = os.getenv("TELNYX_S3_BUCKET")
    if not name:
        logger.error("TELNYX_S3_BUCKET is not set in the environment.")
        raise RuntimeError("TELNYX_S3_BUCKET is required")
    return name

####################################################
#--- Fonctions complementaires ---
####################################################

# --- Extraction de l'adresse courriel ---
def extract_email(raw_email: str) -> str:
    decoded = html.unescape(raw_email or "")
    logger.debug(f"Decoded email input: {decoded}")
    emails = re.findall(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+", decoded)
    if emails:
        logger.debug(f"Extracted emails: {emails}")
        return emails.pop().lower()
    match = re.search(r"<([^<>]+)>", decoded)
    if match:
        candidate = match.group(1)
        logger.debug(f"Fallback extracted from angle brackets: {candidate}")
        return candidate.lower()
    logger.warning(f"No email found in input: {raw_email}")
    return None

# --- Association du numero de telephone à une adresse courriel ---
def get_phone_number_from_email(email: str):
    for record in DB:
        if record["email"].lower() == email.lower():
            return record["phone_number"]
    return False

# --- Association d'une adresse courriel à numero de telephone ---
def get_email_from_phone_number(phone_number: str):
    for record in DB:
        if record["phone_number"] == phone_number:
            return record["email"]
    return False

# --- Definition des types de fichiers permis ---
def allowed_file(filename: str) -> bool:
    allowed_extensions = {"txt", "pdf"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions

# --- Telechargement des fichiers de piece jointe vers le dossier "downloads" ---
def download_file(url: str) -> str:
    r = requests.get(url, allow_redirects=True)
    r.raise_for_status()
    file_name = os.path.basename(urlparse(url).path) or "attachment"
    file_path = os.path.join(DOWNLOAD_DIR, file_name)
    with open(file_path, "wb") as f:
        f.write(r.content)
    return file_path

# --- Televersement des fichiers de piece jointe vers S3 ---
def upload_to_s3(file_path: str, file_name: str) -> str:
    bucket = get_bucket_name()
    logger.debug(f"Uploading {file_path} to bucket {bucket} as {file_name}")
    try:
        get_s3_client().upload_file(file_path, bucket, file_name, ExtraArgs={"ContentType": "application/pdf"})
    except NoCredentialsError:
        logger.error("AWS credentials not found. Set env vars or attach an IAM role.")
        raise
    return file_name

# --- Generation d'un URL temporaire pour la recuperation du fichier a partir de S3 ---
def generate_presigned_url(file_name: str, expiration: int = 3600) -> str:
    url = get_s3_client().generate_presigned_url(
        "get_object",
        Params={"Bucket": get_bucket_name(), "Key": file_name, "ResponseContentType": "application/pdf"},
        ExpiresIn=expiration,
    )
    logger.debug(f"Generated pre-signed URL: {url}")
    return url

# --- Envoi du courriel par l'API de Mailgun ---
def send_email(file_name: str, from_phone_number: str, to_phone_number: str, email: str):
    auth = ("api", MAILGUN_API_KEY)
    files = [("attachment", (file_name, open(file_name, "rb").read()))]
    email_uri = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"
    email_result = requests.post(
        email_uri,
        auth=auth,
        files=files,
        data={
            "from": f"{from_phone_number} <{from_phone_number}@{MAILGUN_DOMAIN}>",
            "to": email,
            "subject": f"Fax recu au numero {to_phone_number} de {from_phone_number}",
            "text": f"Vous avez recu un fax au numero {to_phone_number} de la part de {from_phone_number}. Vous trouverez le fichier en piece jointe.",
        },
    )
    return email_result

# --- Confirmation par courriel de la transmission du fax ---
def send_delivery_notification_email(notify_email: str, fax_id: str, to_number: str, from_number: str, file_name: str = None):
    auth = ("api", MAILGUN_API_KEY)
    email_uri = f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages"

    subject = "Confirmation de transmission de fax"
    text_lines = [
        "Bonjour,",
        "",
        "Votre fax a été transmis avec succès.",
        "",
        "Détails de la transmission:",
        "",
        f" - Fax ID: {fax_id}",
        f" - De: {from_number}",
        f" - Vers: {to_number}",
        f" - Fichier: {file_name}",
        "",
        "",
        "Merci et bonne journée",
    ]
#    if file_name:
#        text_lines.append(f" - Fichier: {file_name}")

    return requests.post(
        email_uri,
        auth=auth,
        data={
            "from": f"Service de fax <fax@{MAILGUN_DOMAIN}>",
            "to": notify_email,
            "subject": subject,
            "text": "\n".join(text_lines),
        },
        timeout=15
    )

####################################################
#--- Configuration des taches Celery ---
####################################################

@celery.task(bind=True, max_retries=3)
def send_fax_task(self, file_path, file_name, to_number, from_number, connection_id, notify_email=None):
    try:
        s3_key = upload_to_s3(file_path, file_name)
        presigned_url = generate_presigned_url(s3_key)
        fax_response = client.faxes.create(
            connection_id=connection_id,
            to=to_number,
            from_=from_number,
            media_url=presigned_url
        )
        fax_id = getattr(fax_response.data, 'id', None)
        status = getattr(fax_response.data, 'status', None)
        if status and status.lower() == "fail":
            raise Exception("Fax failed")
        logger.info(f"Sent fax with fax_id: {fax_id}")
        set_fax_file(fax_id, file_path)

        if notify_email:
            try:
                set_fax_meta(
                    fax_id,
                    {
                        "notify_email": notify_email,
                        "to_number": to_number,
                        "from_number": from_number,
                        "file_name": file_name
                    }
                )
                logger.debug("Stored fax meta for notification. fax_id=%s notify_email=%s", fax_id, notify_email)
            except Exception:
                logger.warning("Failed to store fax meta for fax_id=%s", fax_id, exc_info=True)

        return fax_id
    except Exception as exc:
        logger.warning("Fax send failed; retrying in 5 minutes (attempt %s/%s). Error: %s",
                       self.request.retries + 1, self.max_retries, exc, exc_info=True)
        raise self.retry(exc=exc, countdown=300)

@celery.task(bind=True, max_retries=3)
def send_email_task(self, attachment, from_number, to_number, email):
    try:
        email_response = send_email(attachment, from_number, to_number, email)
        if email_response.status_code == 200:
            try:
                response_json = email_response.json()
                logger.info(f"Sent email with id: {response_json.get('id')}")
            except json.JSONDecodeError:
                logger.error(f"Failed to decode JSON. Raw response: {email_response.text}")
        else:
            logger.error(f"Email API returned status {email_response.status_code}: {email_response.text}")
        return email_response.text
    except Exception as exc:
        logger.error("Error sending email", exc_info=True)
        raise self.retry(exc=exc, countdown=300)

@celery.task(bind=True, max_retries=3)
def send_delivery_notification_task(self, notify_email, fax_id, to_number, from_number, file_name=None):
    try:
        resp = send_delivery_notification_email(
            notify_email=notify_email,
            fax_id=fax_id,
            to_number=to_number,
            from_number=from_number,
            file_name=file_name
        )

        if resp.status_code == 200:
            try:
                logger.info("Delivery notification email sent: %s", resp.json().get("id"))
            except Exception:
                logger.info("Delivery notification email sent (non-JSON response).")
            return True

        logger.error("Mailgun delivery notification failed (%s): %s", resp.status_code, resp.text)
        raise Exception(f"Mailgun returned {resp.status_code}")
    except Exception as exc:
        logger.error("Error sending delivery notification email", exc_info=True)
        raise self.retry(exc=exc, countdown=300)

@celery.task
def delete_from_s3_task(file_name):
    bucket = get_bucket_name()
    try:
        get_s3_client().delete_object(Bucket=bucket, Key=file_name)
        logger.debug(f"Deleted {file_name} from bucket {bucket}")
    except Exception as e:
        logger.warning(f"Failed to delete {file_name} from S3: {e}")

####################################################
#--- Routes d'application ---
####################################################

# --- Reception de fax envoye par Telnyx et envoye par courriel (Mailgun) ---
@app.route("/faxes", methods=["POST"])
def inbound_message():
    body = json.loads(request.data)
    fax_id = body["data"]["payload"]["fax_id"]
    event_type = body["data"]["event_type"]
    direction = body["data"]["payload"]["direction"]
    logger.info(f"Received fax event_type: {event_type}, direction: {direction}, fax_id: {fax_id}")

    # Gestion des evenements "fax.received" de la part de Telnyx
    if event_type == "fax.received" and direction == "inbound":
        to_number = body["data"]["payload"]["to"]
        from_number = body["data"]["payload"]["from"]
        media_url = body["data"]["payload"]["media_url"]
        attachment = download_file(media_url)
        set_fax_file(fax_id, attachment)
        email = get_email_from_phone_number(to_number)
        if not email:
            logger.warning(f"No association for phone number: {to_number}")
            return Response(status=200)
        try:
            send_email_task.delay(attachment, from_number, to_number, email)
            logger.info(f"Queued email sending task for fax_id: {fax_id}")
        except Exception as e:
            logger.error("Error queuing email sending task", exc_info=True)

    elif event_type in ("fax.delivered", "fax.email.delivered"):
        if direction == "outbound":
            meta = get_fax_meta(fax_id)
            if meta and meta.get("notify_email"):
                if mark_fax_notified_once(fax_id):
                    try:
                        send_delivery_notification_task.delay(
                            notify_email=meta.get("notify_email"),
                            fax_id=fax_id,
                            to_number=meta.get("to_number"),
                            from_number=meta.get("from_number"),
                            file_name=meta.get("file_name")
                        )
                        logger.info("Queued delivery notification email for outbound fax_id: %s", fax_id)
                    except Exception:
                        logger.error("Error queuing delivery notification email", exc_info=True)
                else:
                    logger.debug("Delivery notification already sent for fax_id: %s", fax_id)

            delete_fax_meta(fax_id)

        file_path = get_fax_file(fax_id)
        delete_fax_file(fax_id)

        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.debug(f"Deleted delivered fax file: {file_path}")
                file_name = os.path.basename(file_path)
                delete_from_s3_task.delay(file_name)
            except Exception as cleanup_error:
                logger.warning(f"Failed to delete file {file_path}: {cleanup_error}")
        else:
            logger.debug(f"No file found for fax_id {fax_id} during cleanup")

        return Response(status=200)

    logger.debug(f"Ignoring unhandled fax event_type: {event_type}, direction: {direction}, fax_id: {fax_id}")
    return Response(status=200)


# --- Reception de fax envoye par courriel (Mailgun) et envoye vers Telnyx ---
@app.route("/email/inbound", methods=["POST"])
def inbound_email():
    connection_id = os.getenv("TELNYX_FAX_CONNECTION_ID")
    data = dict(request.form)
    logger.debug(f"Received form data: {data}")

    timestamp = data.get("timestamp", "")
    token = data.get("token", "")
    signature = data.get("signature", "")

    if not all([timestamp, token, signature]):
        logger.warning("Missing signature fields in webhook payload.")
        return Response(status=403)

    if not verify_mailgun_signature(timestamp, token, signature):
        return Response(status=403)

    try:
        to_field = data["To"]
        to_number_raw = to_field.split("@")[0].strip().strip("'").strip('"')
        to_phone_number = "+" + to_number_raw.lstrip("+")
        logger.debug(f"Extracted to_phone_number: {to_phone_number}")
    except Exception:
        logger.error("Failed to extract 'To' phone number", exc_info=True)
        return Response(status=400)
    from_email_raw = data.get("From", "")
    from_email = extract_email(from_email_raw)
    from_phone_number = get_phone_number_from_email(from_email)
    if not from_phone_number:
        logger.warning(f"No phone number found for sender email: {from_email}")
        return Response(status=200)
    logger.debug(f"Using from_phone_number: {from_phone_number}")
    attachment_count = int(data.get("attachment-count", "0"))
    if attachment_count == 0 or not from_phone_number:
        logger.warning("No attachment or from_phone_number missing")
        return Response(status=200)
    processed = False
    for i in range(1, attachment_count + 1):
        file = request.files.get(f"attachment-{i}")
        if not file:
            logger.warning(f"No attachment-{i} found in request")
            continue
        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            logger.warning(f"File {filename} is not an allowed type (extension check)")
            continue
        if file.mimetype not in ["application/pdf", "text/plain"]:
            logger.warning(f"File {filename} has disallowed MIME type {file.mimetype}")
            continue
        file_path = os.path.join(DOWNLOAD_DIR, filename)
        file.save(file_path)
        logger.debug(f"Saved attachment as {filename}")
        try:
            result = send_fax_task.delay(
                file_path=file_path,
                file_name=filename,
                to_number=to_phone_number,
                from_number=from_phone_number,
                connection_id=connection_id,
                notify_email=from_email
            )
            logger.info(f"Queued outbound fax task for {filename}, Celery task id: {result.id}")
            processed = True
        except Exception as e:
            logger.error(f"Failed to queue outbound fax: {e}", exc_info=True)
    if not processed:
        logger.warning("No valid attachment processed")
    return Response(status=200)



# --- Route d'application par défaut ---
@app.route("/", methods=["POST"])
def respond_to_tests():
    return Response(status=200)

####################################################
#--- Application ---
####################################################

if __name__ == "__main__":
    load_dotenv(find_dotenv(), override=False)
    PORT = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=PORT)