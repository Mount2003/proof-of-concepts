from __future__ import print_function
import os.path
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from apiclient import errors
import mimetypes
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
from email import encoders

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def create_message_with_attachment(sender, to, subject, message_text, file):
    """Create a message with an attachment."""
    message = MIMEMultipart()
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    
    msg = MIMEText(message_text)
    message.attach(msg)

    content_type, encoding = mimetypes.guess_type(file)

    if content_type is None or encoding is not None:
        content_type = 'application/octet-stream'

    main_type, sub_type = content_type.split('/', 1)
    
    # Read the file and prepare the attachment
    part = MIMEBase(main_type, sub_type)
    part.set_payload(open(file, "rb").read())
    
    # Correctly encode the payload using the standard library encoder
    encoders.encode_base64(part)
    
    # Add headers for the attachment
    part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(file))
    
    # Correctly attach the MIMEBase object to the main message
    message.attach(part)

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_email_with_attachment(sender_email, to_email, subject, message_body, file_path):
    """Sends an email with an attachment via the Gmail API."""
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('Secrets/token.json'):
        creds = Credentials.from_authorized_user_file('Secrets/token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'Secrets/credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('Secrets/token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)
        message = create_message_with_attachment(
            sender_email, to_email, subject, message_body, file_path
        )
        send_message = (service.users().messages().send(
            userId="me", body=message).execute())
        print('Message Id: %s' % send_message['id'])
    except errors.HttpError as error:
        print('An error occurred: %s' % error)