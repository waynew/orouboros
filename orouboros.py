'''
orouboros --cert /path/to/your/certfile.pem
          --key /path/to/your/keyfile.pem
          --host '0.0.0.0'
          --port 25
          --ssl-port 587
          --forward-host example.com
          --forward-port 587
          --mboxdir /path/to/maildir
          --forward
          --local
'''
import argparse
import base64
import email.parser
import logging
import mailbox
import os
import signal
import smtplib
import socket
import ssl

from contextlib import contextmanager
from enum import Enum
from hashlib import sha1
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Mailbox
from aiosmtpd.smtp import SMTP as Server, syntax, MISSING, Session


__version__ = '0.1.11'
logger = logging.getLogger('orouboros')


def make_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=2500)
    parser.add_argument('--ssl-port', type=int, required=False)
    parser.add_argument('--local', action='store_true')
    parser.add_argument('--forward', action='store_true')
    parser.add_argument('--forward-host', default='127.0.0.1')
    parser.add_argument('--forward-port', type=int, default=2501)
    parser.add_argument('--log', default='/tmp/mail.log')
    parser.add_argument('--log-level', type=str.upper, default='WARN')
    parser.add_argument('--forward-domain', action='append', required=True)
    parser.add_argument('--mboxdir', type=Path)
    return parser


def validate_credentials(username, password):
    # TODO: Stop logging these -W. Werner, 2018-03-01
    logger = logging.getLogger('orouboros.validate_credentials')
    logger.debug(f'Credentials: {username!r} {password!r}')
    return username == 'fnord' and password == 'fnord'


@contextmanager
def get_mbox(mbox_dir, local_part):
    mbox_path = mbox_dir / 'fnord' / 'INBOX'
    logger.debug(f'Ensuring mbox {str(mbox_path)!r} exists')
    mbox_path.parent.mkdir(parents=True, exist_ok=True)
    if not mbox_path.exists():
        mbox_path.touch()

    mbox = mailbox.mbox(mbox_path)
    try:
        mbox.lock()
        yield mbox
    finally:
        mbox.unlock()



class AuthStatus(Enum):
    ok = '235 2.7.0  Authentication Succeeded'
    invalid = '535 5.7.8  Authentication credentials invalid'
    transition_needed = '432 4.7.12  A password transition is needed'
    temp_failure = '454 4.7.0  Temporary authentication failure'
    mechanism_too_weak = '534 5.7.9  Authentication mechanism is too weak'
    line_too_long = '500 5.5.6  Authentication Exchange line is too long'


class AuthSession(Session):
    def __init__(self, loop):
        super().__init__(loop=loop)
        self.is_authenticated = False


class AuthServer(Server):
    def __init__(self, *args, ident=None, **kwargs):
        # TODO: When a release of aiosmtpd is out, ident can be put in factory()  -W. Werner, 2018-03-01
        super().__init__(*args, **kwargs)
        self.__ident__ == 'orouboros SMTP 1.1'

    @syntax('AUTH protocol data')
    async def smtp_AUTH(self, arg):
        if not arg:
            await self.push('250 AUTH PLAIN')
            return
        # People try haxoring
        protocol, credentials, *_ = arg.split(' ', maxsplit=1) + ['', '']
        if not any(credentials):
            await self.push("334 ")  # gimme more gimme more!
            line = await self._reader.readline()
            credentials = line.strip().decode()
            if credentials == '*':
                await self.push("501 Auth aborted")
                return

        status = await self._call_handler_hook('AUTH', protocol, credentials)
        if status is MISSING:
            ...  #blarg
        elif status is AuthStatus.ok:
            self.session.is_authenticated = True
        logger.debug(f'Returning {status}')
        await self.push(status.value if status in AuthStatus else status)

    def _create_session(self):
        return AuthSession(loop=self.loop)



class AuthController(Controller):
    def __init__(self, *args, starttls_context, **kwargs):
        super().__init__(*args, **kwargs)
        self.starttls_context = starttls_context

    def factory(self):
        return AuthServer(
            self.handler,
            hostname=self.hostname,
            tls_context=self.starttls_context,
        )


class ForwardingHandler:
    def __init__(self, *, forward_host, forward_port, ok_domains):
        self.forward_host = forward_host
        self.forward_port = forward_port
        self.ok_domains = ok_domains

    async def handle_exception(self, error):
        logger.warn(f'{error} caught')
        return '542 internal server error'

    async def handle_EHLO(self, server, session, envelope, hostname):
        session.host_name = hostname
        return '250-AUTH PLAIN\n250-STARTTLS\n250 HELP'

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        logger.debug(f'Sending mail to {address}')
        # TODO: this is where address checking should happen -W. Werner, 2018-03-08
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        logger.debug(f'Session auth? {session.is_authenticated}')
        logger.debug(f'Message is from {envelope.mail_from!r}')
        logger.debug(f'Message is for {envelope.rcpt_tos!r}')
        try:
            with smtplib.SMTP_SSL(self.forward_host, self.forward_port, timeout=10) as smtp:
                smtp.login('fnord', 'fnord')
                logger.debug('Sending message...')
                smtp.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.content)
                logger.debug('Message sent!')
        except socket.timeout:
            return '450 Mailbox busy, try again later'
        return '250 Message accepted for delivery, eh?'

    async def handle_AUTH(self, server, session, envelope, protocol, credentials):
        username, password = base64.b64decode(
            credentials.encode()
        ).lstrip(b'\x00').decode().split('\x00')
        if validate_credentials(username, password):
            return AuthStatus.ok
        else:
            return AuthStatus.invalid


class LocalHandler:
    def __init__(self, *, ok_domains, mbox_dir):
        self.ok_domains = ok_domains
        self.mbox_dir = mbox_dir

    async def handle_EHLO(self, server, session, envelope, hostname):
        session.host_name = hostname
        return '250-AUTH PLAIN\n250 HELP'

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        logger.debug(f'Sending mail to {address}')
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_AUTH(self, server, session, envelope, protocol, credentials):
        username, password = base64.b64decode(
            credentials.encode()
        ).lstrip(b'\x00').decode().split('\x00')
        if validate_credentials(username, password):
            return AuthStatus.ok
        else:
            return AuthStatus.invalid

    async def handle_DATA(self, server, session, envelope):
        logger = logging.getLogger('orouboros.localhandler')
        logger.debug(f'Session auth? {session.is_authenticated}')
        logger.debug(f'Message is from {envelope.mail_from!r}')
        logger.debug(f'Message is for {envelope.rcpt_tos!r}')
        valid_recipients = [
            recipient
            for recipient in envelope.rcpt_tos
            if recipient.rpartition('@')[2] in self.ok_domains
        ]

        # TODO: remove False and -W. Werner, 2018-03-01
        if False and not valid_recipients:
            logger.error(f'No valid recipients in {envelope.rcpt_tos}')
            return '554 Transaction failed'
        else:
            logger.info(f'Sending mail to {valid_recipients}')
            parser = email.parser.BytesParser()
            msg = parser.parsebytes(envelope.original_content)
            for recipient in valid_recipients:
                local_part, _, domain = recipient.rpartition('@')
                with get_mbox(self.mbox_dir, local_part) as mbox:
                    mbox.add(msg)

        return '250 Message accepted for delivery, eh?'


def run():
    parser = make_argparser()
    args = parser.parse_args()

    logger.addHandler(logging.FileHandler(args.log))
    logger.setLevel(getattr(logging, args.log_level))

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(args.cert, args.key)

    if args.local:
        if args.mboxdir is None:
            parser.error('--local requires --mboxdir')
        else:
            logger.debug('Ensuring mbox path exists')
            args.mboxdir.mkdir(parents=True, exist_ok=True)

    controllers = []
    if args.forward:
        controllers.append(
            AuthController(
                ForwardingHandler(
                    ok_domains=args.forward_domain,
                    forward_host=args.forward_host,
                    forward_port=args.forward_port,
                ),
                port=args.port,
                hostname=args.host,
                starttls_context=context,
            )
        )
        if args.ssl_port:
            controllers.append(
                AuthController(
                    ForwardingHandler(
                        ok_domains=args.forward_domain,
                        forward_host=args.forward_host,
                        forward_port=args.forward_port,
                    ),
                    port=args.ssl_port,
                    hostname=args.host,
                    starttls_context=context,
                    ssl_context=context,
                )
            )

    if args.local:
        controllers.append(
            AuthController(
                LocalHandler(
                    ok_domains=args.forward_domain,
                    mbox_dir=args.mboxdir,
                ),
                port=args.forward_port,
                hostname='0.0.0.0',
                ssl_context=context,
                starttls_context=context,
            )
        )

    logger.warn(f'orouboros {__version__} staring with pid {os.getpid()}')
    for controller in controllers:
        logger.debug(f'starting controller {controller}')
        controller.start()

    if controllers:
        logger.info('Waiting for SIGINT or SIGQUIT')
        sig = signal.sigwait([signal.SIGINT, signal.SIGQUIT])
        logger.warn(f'{sig} caught, shutting down')
    else:
        print('Specify at least one of --forward or --local on the command line')

    for controller in controllers:
        logger.debug(f'stopping controller {controller}')
        controller.stop()
