import datetime
import os

import jwt
import psycopg2
import requests
import sendgrid
from dotenv import load_dotenv
from flask import Flask, jsonify, make_response, request
from flask_cors import CORS
from jwt import ExpiredSignatureError, InvalidSignatureError, MissingRequiredClaimError
from marshmallow import fields, Schema, ValidationError
from requests import RequestException
from sendgrid import Email, To, Content, Mail

load_dotenv()

recaptcha_secret = os.getenv('RECAPTCHA_SECRET')
jwt_secret = os.getenv('JWT_SECRET')
expiry = 30  # in minutes

app = Flask(__name__)
CORS(app)

RequestInviteSchema = Schema.from_dict({'email': fields.Email(required=True), 'captcha': fields.String(required=True)})
InvitationTokenSchema = Schema.from_dict({'token': fields.String(required=True)})


@app.get("/v1/onboarding/invitation/verify")
def verify_invitation():
    token = request.args.get('token', '')

    try:
        InvitationTokenSchema().load({'token': token})
    except ValidationError:
        return {'message': 'Invalid token'}, 400

    try:
        jwt.decode(token, jwt_secret, algorithms="HS256", options={'verify_signature': True, 'require': ['exp']})
    except ExpiredSignatureError:
        return {'message': 'Token has expired'}, 401
    except InvalidSignatureError:
        return {'message': 'Invalid token'}, 401
    except MissingRequiredClaimError:
        return {'message': 'Expired token'}, 401

    return {'message': 'valid'}, 200


@app.post("/v1/onboarding/invitation/request")
def request_invite():
    post_data = request.get_json()

    try:
        RequestInviteSchema().load(post_data)
    except ValidationError as err:
        print(err)
        return {'message': 'Invalid data.'}, 400

    captcha = post_data['captcha']
    if not is_captcha_valid(captcha):
        return {'message': 'Invalid captcha.'}, 400

    email_address = post_data['email']
    if not does_email_exist(email_address):
        mark_invite_pending(email_address)
        return {'message': 'Email has not been verified. Someone from the support team will reach out shortly.'}, 404

    email_invitation = fetch_email_invitation(email_address)

    if not email_invitation.is_verified():
        return {'message': 'Email is pending verification.'}, 400

    if email_invitation.get_status() == 'SUCCESS':
        return {'message': 'Invitation has already been sent.'}, 400

    send_invite(email_address)

    return {'message': 'ok'}, 200


@app.errorhandler(404)
def resource_not_found(e):
    return make_response(jsonify(error='Not found!'), 404)


def is_captcha_valid(token: str):
    try:
        query_params = {'secret': recaptcha_secret, 'response': token}
        response = requests.get('https://www.google.com/recaptcha/api/siteverify', params=query_params).json()
    except RequestException:
        return False

    return response['success'] == True


def get_dbconn():
    conn = psycopg2.connect(
        dbname="juryanalyst",
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASS'),
        port="5432"
    )
    conn.autocommit = True
    return conn


def fetch_email_invitation(email: str):
    dbConn = get_dbconn()
    cursor = dbConn.cursor()

    cursor.execute("""
        SELECT e.email_id
             , e.email_address
             , e.verified
             , o.status
          FROM emails e
          JOIN onboarding_invites o ON e.email_id = o.email_id
         WHERE e.email_address = %s  
    """, (email,))

    result = cursor.fetchone()

    email_invitation = EmailInvitation(*result)

    cursor.close()
    dbConn.close()

    return email_invitation


def does_email_exist(email: str):
    dbConn = get_dbconn()

    cursor = dbConn.cursor()
    cursor.execute("""
        SELECT 1 FROM emails WHERE email_address = %s
    """, (email,))

    result = cursor.fetchone()

    cursor.close()
    dbConn.close()

    return result is not None


def mark_invite_pending(email):
    dbConn = get_dbconn()

    cursor = dbConn.cursor()

    cursor.execute("""
        INSERT INTO emails (email_address, verified) VALUES (%s, %s) RETURNING email_id
    """, (email, False))
    email_id = cursor.fetchone()[0]

    cursor.execute("""
        INSERT INTO onboarding_invites (email_id, status) VALUES (%s, %s)
    """, (email_id, "PENDING"))

    cursor.close()
    dbConn.close()


def create_signed_url(payload=None):
    if payload is None:
        payload = {}

    token = jwt.encode(payload, jwt_secret, algorithm="HS256")

    return f"https://juryanalyst.com/onboarding/?token={token}"


def send_invite(email):
    signed_url = create_signed_url({
        "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(minutes=expiry),
        "email": email
    })

    sg = sendgrid.SendGridAPIClient(os.getenv('SEND_GRID_API_KEY'))
    from_email = Email("onboarding@juryanalyst.com")
    to_email = To(email)
    subject = "Invitation"
    content = Content(
        "text/html",
        f"""
            <h1> Hello,</h1>
            <p>
                Accept invitation.
            </p>
            
            <a href='{signed_url}'> Accept </>
        """
    )
    # settings = MailSettings(sandbox_mode=True)
    mail = Mail(from_email, to_email, subject, content)

    mail_json = mail.get()

    response = sg.client.mail.send.post(request_body=mail_json)

    status = 'SUCCESS' if response.status_code <= 400 else "FAILED"
    dbConn = get_dbconn()
    cursor = dbConn.cursor()

    cursor.execute("SELECT email_id FROM emails WHERE email_address = %s", (email,))
    email_id = cursor.fetchone()[0]

    cursor.execute("""
        INSERT INTO onboarding_invites 
                    (email_id, status) 
             VALUES (%s, %s) 
        ON CONFLICT (email_id) 
          DO UPDATE SET last_updated = current_timestamp, status = %s
    """, (email_id, status, status))

    cursor.close()
    dbConn.close()

    return status == 'SUCCESS'


class EmailInvitation:
    def __init__(self, email_id, email_address, verified, status):
        self.__email_id = email_id
        self.__email_address = email_address,
        self.__verified = verified
        self.__status = status

    def get_email_id(self):
        return self.__email_address

    def get_email_address(self):
        return self.__email_address

    def is_verified(self):
        return self.__verified

    def get_status(self):
        return self.__status
