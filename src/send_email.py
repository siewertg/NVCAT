import smtplib, ssl

# Send email with body to recipient
# Source: https://realpython.com/python-send-email/#option-1-setting-up-a-gmail-account-for-development
def notify(recipient, body):
    port = 465
    smtp_server = "smtp.gmail.com"
    sender = input("Enter sender email address: ")
    password = input("Enter password for sender email account: ")
    subject = "NVCAT: Summary Report"
    message = "Subject: "+subject+"\r\n"+body
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=ctx) as server:
        server.login(sender, password)
        server.sendmail(sender, recipient, message)

