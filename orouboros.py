'''
orouboros --cert /etc/letsencrypt/live/www.waynewerner.com/fullchain.pem \
          --key /etc/letsencrypt/live/www.waynewerner.com/privkey.pem \
          --host '0.0.0.0'
          --port 2500
          --
'''
import asyncio
import ssl

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Mailbox


context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#context.load_cert_chain(
#    '/etc/letsencrypt/live/www.waynewerner.com/fullchain.pem'
#    '/etc/letsencrypt/live/www.waynewerner.com/privkey.pem'
#)


class ForwardingHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        print(f'Sending mail to {address}')
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        print(f'Message is from {envelope.mail_from!r}')
        print(f'Message is for {envelope.rcpt_tos!r}')
        print(f'Message data:\n{envelope.content.decode("utf8", errors="replace")}\nEOF')
        return '250 Message accepted for delivery, eh?'


def run():
    controllers = [
        Controller(ForwardingHandler(), port=2500, hostname='0.0.0.0'),
    ]
    for controller in controllers:
        controller.start()

    input('Press <enter> to stop')

    for controller in controllers:
        controller.stop()
    print('awesome')
