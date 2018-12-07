import datetime as dt
import signal
import smtplib
import time
import socket
import asyncio
import unittest

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import SMTP as Server, __ident__ as GREETING
from aiosmtpd.testing.helpers import reset_connection
from contextlib import ExitStack
from email.mime.text import MIMEText
from smtplib import (
    SMTP
)
from unittest.mock import Mock, PropertyMock, patch


CRLF = '\r\n'
BCRLF = CRLF.encode()


class Blerp:
    box = None

    def __init__(self):
        self.box = []
        self.blerps = []

    async def handle_EHLO(self, server, session, envelope, hostname):
        session.host_name = hostname
        return '250-AUTH PLAIN\n250-STARTTLS\n250 HELP'

    async def handle_DATA(self, server, session, envelope):
        self.box.append(envelope)
        self.blerps.append('what')
        return '250 OK'

    async def handle_AUTH(self, server, session, envelope, protocol, credentials):
        print('ok')
        self.blerps.append(credentials)
        username, password, *_ = base64.b64decode(
            credentials.encode()
        ).lstrip(b'\x00').decode().split('\x00') + ['', '']
        if validate_credentials(username, password):
            return AuthStatus.ok
        else:
            return AuthStatus.invalid


class Clerp(Controller):
    def factory(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain('cert.pem', 'cert.key')
        return Server(self.handler, tls_context=context)


#class TestOrouboros(unittest.TestCase):
#    def setUp(self):
#        self.transport = Mock()
#        self.transport.write = self._write
#        self.responses = []
#        self._old_loop = asyncio.get_event_loop()
#        self.loop = asyncio.new_event_loop()
#        asyncio.set_event_loop(self.loop)
#
#    def tearDown(self):
#        self.loop.close()
#        asyncio.set_event_loop(self._old_loop)
#
#    def _write(self, data):
#        self.responses.append(data)
#
#    def _get_protocol(self, *args, **kwargs):
#        protocol = Server(*args, loop=self.loop, **kwargs)
#        protocol.connection_made(self.transport)
#        return protocol
#
#    def test_thing(self):
#        handler = Blerp()
#        data = b'This is my message'
#        protocol = self._get_protocol(handler)
#        protocol.data_received(BCRLF.join([
#            b'EHLO example.org',
#            b'MAIL FROM: <me@example.com>',
#            b'RCPT TO: <you@example.com>',
#            b'DATA',
#            data,
#            BCRLF+b'.',
#            b'QUIT',
#            BCRLF,
#        ]))
#        try:
#            self.loop.run_until_complete(protocol._handler_coroutine)
#        except asyncio.CancelledError:
#            pass
#        self.assertEqual(handler.box[0].content, 'whatever')
#
class TestOrberyrbp(unittest.TestCase):
    def setUp(self):
        self._handler = Blerp()
        self.controller = Clerp(self._handler, port=44555)
        self.controller.start()
        self.addCleanup(self.controller.stop)
        self._address = (self.controller.hostname, self.controller.port)

    def test_another_thing(self):
        with SMTP(*self._address) as client:
            client.ehlo('example.com')
            client.login('foo', 'bar')
        try:
            self.loop.run_until_complete(protocol._handler_coroutine)
        except asyncio.CancelledError:
            pass
        self.assertEqual(self.handler.blerps, ['asdf'])

#EMAILS_TO_SEND = 1


#def test_one():
#    print('Waiting')
#    now = time.time()
#    signal.sigwait([signal.SIGQUIT])
#    print('Waited for', time.time()-now)
#
#
#def test_two():
#    #with smtplib.SMTP_SSL('localhost', 2500) as smtp:
#    with smtplib.SMTP_SSL('mail.waynewerner.com', 587) as smtp:
#        #smtp.login('fnord', 'fnord')
#        for _ in range(EMAILS_TO_SEND):
#            msg = MIMEText(f'This\n\tis\n\t\tan email!\n{dt.datetime.now()}')
#            msg['Subject'] = 'This subject is a tautology too'
#            msg['From'] = 'wherever@example.com'
#            #msg['To'] = 'someone@example.com, someoneelse@example.org, fnord@qq.com'
#            msg['To'] = 'fnord@qq.com'
#            smtp.send_message(msg)
#    print('woo')
#
#
#if __name__ == '__main__':
#    test_two()
