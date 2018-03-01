import datetime as dt
import signal
import smtplib
import time

from email.mime.text import MIMEText


EMAILS_TO_SEND = 1


def test_one():
    print('Waiting')
    now = time.time()
    signal.sigwait([signal.SIGQUIT])
    print('Waited for', time.time()-now)


def test_two():
    with smtplib.SMTP_SSL('localhost', 2500) as smtp:
        #smtp.login('fnord', 'fnord')
        for _ in range(EMAILS_TO_SEND):
            msg = MIMEText(f'This\n\tis\n\t\tan email!\n{dt.datetime.now()}')
            msg['Subject'] = 'This subject is a tautology too'
            msg['From'] = 'wherever@example.com'
            msg['To'] = 'someone@example.com, someoneelse@example.org'
            smtp.send_message(msg)
    print('woo')


if __name__ == '__main__':
    test_two()
