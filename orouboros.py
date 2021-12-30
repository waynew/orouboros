"""
orouboros --cert /path/to/your/certfile.pem
          --key /path/to/your/keyfile.pem
          --host '0.0.0.0'
          --port 25
          --ssl-port 587
          --forward-host example.com
          --forward-port 587
          --mboxdir /path/to/maildir
          --user-credentials /path/to/credentials.json
          --forward
          --local
"""

import argparse
import base64
import email.parser
import email.utils
import hmac
import json
import logging
import logging.handlers
import mailbox
import os
import re
import signal
import smtplib
import socket
import ssl
import time

from contextlib import contextmanager
from datetime import datetime
from enum import Enum
from hashlib import sha1, pbkdf2_hmac
from pathlib import Path

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Mailbox
from aiosmtpd.smtp import SMTP as Server, syntax, MISSING, Session


__version__ = "0.1.13"
logger = logging.getLogger("orouboros")


def make_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2500)
    parser.add_argument("--ssl-port", type=int, required=False)
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--forward", action="store_true")
    parser.add_argument("--forward-host", default="127.0.0.1")
    parser.add_argument("--forward-port", type=int, default=2501)
    parser.add_argument(
        "--log",
        default="/tmp/mail.log",
        help="Path to log file. If STDERR or STDOUT, those will be used instead of a file.",
    )
    parser.add_argument("--log-level", type=str.upper, default="WARN")
    parser.add_argument("--forward-domain", action="append", required=True)
    parser.add_argument("--delivery-domain", action="append", required=True)
    parser.add_argument("--mboxdir", type=Path)
    parser.add_argument("--wmaildir", type=Path)
    parser.add_argument(
        "--user-credentials",
        type=Path,
        default=Path("creds.json"),
        help="Path to user credentials for AUTH LOGIN",
    )
    parser.add_argument(
        "--sender-blocklist",
        type=Path,
        default=None,
        help="Optional blocklist for senders. If MAIL FROM comes from one of these senders, the mail will be rejected. Other headers should also be inspected.",
    )
    parser.add_argument(
        "--sender-domain-blocklist",
        type=Path,
        default=None,
        help="Optional domain blocklist. If any sender comes from these domains, the mail will be rejected.",
    )
    return parser


class Authenticator:
    """
    A class for verifying credentials.
    """

    def __init__(self, cred_filename):
        self.logger = logging.getLogger("orouboros.auth")
        with open(cred_filename) as f:
            self._creds = json.load(f)

    def validate_credentials(self, username, password):
        self.logger.debug("Checking %r %r", username, password)
        factor = self._creds.get("work_factor", 100_000)
        salt = (
            base64.b64decode(self._creds.get(username, {}).get("salt", b""))
            or b"sodium chloride"
        )
        current_hash = base64.b64decode(
            self._creds.get(username, {}).get("hash", "").encode()
        )
        check_digest = pbkdf2_hmac("sha256", password.encode(), salt, factor)
        self.logger.debug(
            "Factor: %r - Digest: %r - Salt: %r", factor, check_digest, salt
        )
        return hmac.compare_digest(current_hash, check_digest)


@contextmanager
def get_mbox(mboxdir, local_part):
    mbox_path = mboxdir / local_part / "INBOX"
    logger.debug(f"Ensuring mbox {str(mbox_path)!r} exists")
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
    ok = "235 2.7.0  Authentication Succeeded"
    invalid = "535 5.7.8  Authentication credentials invalid"
    transition_needed = "432 4.7.12  A password transition is needed"
    temp_failure = "454 4.7.0  Temporary authentication failure"
    mechanism_too_weak = "534 5.7.9  Authentication mechanism is too weak"
    line_too_long = "500 5.5.6  Authentication Exchange line is too long"


class AuthSession(Session):
    def __init__(self, loop):
        super().__init__(loop=loop)
        self.is_authenticated = False


class AuthServer(Server):
    def __init__(self, *args, ident=None, **kwargs):
        # TODO: When a release of aiosmtpd is out, ident can be put in factory()  -W. Werner, 2018-03-01
        super().__init__(*args, **kwargs)
        self.__ident__ == "orouboros SMTP 1.1"

    @syntax("AUTH protocol data")
    async def smtp_AUTH(self, arg):
        if not arg:
            await self.push("250 AUTH PLAIN")
            return
        # People try haxoring
        protocol, credentials, *_ = arg.split(" ", maxsplit=1) + ["", ""]
        if not any(credentials):
            await self.push("334 ")  # gimme more gimme more!
            line = await self._reader.readline()
            credentials = line.strip().decode()
            if credentials == "*":
                await self.push("501 Auth aborted")
                return

        status = await self._call_handler_hook("AUTH", protocol, credentials)
        if status is MISSING:
            ...  # blarg
        elif status is AuthStatus.ok:
            self.session.is_authenticated = True
        logger.debug(f"Returning {status}")
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
    def __init__(
        self,
        *,
        forward_host,
        forward_port,
        ok_domains,
        authenticator,
        sender_blocklist,
        domain_blocklist,
    ):
        self.forward_host = forward_host
        self.forward_port = forward_port
        self.ok_domains = ok_domains
        self.authenticator = authenticator
        self.sender_blocklist = sender_blocklist
        self.domain_blocklist = domain_blocklist

    async def handle_exception(self, error):
        logger.warn(f"{error} caught")
        return "542 internal server error"

    async def handle_EHLO(self, server, session, envelope, hostname):
        session.host_name = hostname
        return "250-AUTH PLAIN\n250-STARTTLS\n250 HELP"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        logger.debug(f"Sending mail to {address}")
        # TODO: this is where address checking should happen -W. Werner, 2018-03-08
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        logger.debug(f"Session auth? {session.is_authenticated}")
        logger.debug(f"Message is from {envelope.mail_from!r}")
        logger.debug(f"Message is for {envelope.rcpt_tos!r}")
        try:
            with smtplib.SMTP_SSL(
                self.forward_host, self.forward_port, timeout=10
            ) as smtp:
                smtp.login("fnord", "fnord")
                logger.debug("Sending message...")
                smtp.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.content)
                logger.debug("Message sent!")
        except socket.timeout:
            return "450 Mailbox busy, try again later"
        return "250 Message accepted for delivery, eh?"

    async def handle_AUTH(self, server, session, envelope, protocol, credentials):
        data = base64.b64decode(credentials.encode()).lstrip(b"\x00").decode()
        username, _, password = data.partition("\x00")
        if self.authenticator.validate_credentials(username, password):
            return AuthStatus.ok
        else:
            return AuthStatus.invalid


class LocalHandler:
    def __init__(
        self, *, ok_domains, authenticator, sender_blocklist, domain_blocklist
    ):
        self.ok_domains = ok_domains
        self.authenticator = authenticator
        self.sender_blocklist = sender_blocklist
        self.domain_blocklist = domain_blocklist

    def deliver(self, msg, recipients):
        raise NotImplemented("Oh dear, this is not the right handler")

    async def handle_EHLO(self, server, session, envelope, hostname):
        session.host_name = hostname
        return "250-AUTH PLAIN\n250 HELP"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        logger.debug(f"Sending mail to {address} from {envelope.mail_from}")
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_AUTH(self, server, session, envelope, protocol, credentials):
        data = base64.b64decode(credentials.encode()).lstrip(b"\x00").decode()
        username, _, password = data.partition("\x00")
        if self.authenticator.validate_credentials(username, password):
            return AuthStatus.ok
        else:
            return AuthStatus.invalid

    async def handle_DATA(self, server, session, envelope):
        logger = logging.getLogger("orouboros.localhandler")
        logger.debug(f"Session auth? {session.is_authenticated}")
        logger.debug(f"Message is from {envelope.mail_from!r}")
        logger.debug(f"Message is for {envelope.rcpt_tos!r}")

        name, from_addr = email.utils.parseaddr(envelope.mail_from)
        *_, sender_domain = from_addr.rpartition("@")
        if from_addr in self.sender_blocklist or sender_domain in self.domain_blocklist:
            logger.info("Blocked email from %r", envelope.mail_from)
            # TODO Might actually save these to a rubbish bin for later mining
            return "554 Message yeeted for policy reasons"

        valid_recipients = [
            recipient
            for recipient in envelope.rcpt_tos
            if recipient.rpartition("@")[2] in self.ok_domains
        ]
        invalid_recipients = set(envelope.rcpt_tos) - set(valid_recipients)
        if invalid_recipients:
            logger.warn("Invalid recipients removed %r", invalid_recipients)

        if not valid_recipients:
            logger.error(f"No valid recipients in {envelope.rcpt_tos}")
            # TODO Might also save these for later mining
            return "554 Transaction failed"
        else:
            logger.info(f"Sending mail to {valid_recipients}")
            parser = email.parser.BytesParser()
            msg = parser.parsebytes(envelope.original_content)
            self.deliver(msg, valid_recipients)

        return "250 Message accepted for delivery, eh?"


class LocalMboxHandler(LocalHandler):
    def __init__(self, ok_domains, mboxdir, **kwargs):
        super().__init__(ok_domains=ok_domains, **kwargs)
        self.mboxdir = mboxdir

    def deliver(self, msg, recipients):
        valid_recipients = ()
        for recipient in recipients:
            local_part, _, domain = recipient.rpartition("@")
            with get_mbox(self.mboxdir, local_part) as mbox:
                mbox.add(msg)


class LocalWMaildirHandler(LocalHandler):
    def __init__(self, ok_domains, wmaildir, **kwargs):
        super().__init__(ok_domains=ok_domains, **kwargs)
        self.wmaildir = wmaildir

    def deliver(self, msg, recipients):
        # TODO: This should look up a map of WMaildirs -W. Werner, 2019-04-25
        deliver_maildir(msg, self.wmaildir)


def run():
    parser = make_argparser()
    args = parser.parse_args()

    if args.log == "STDOUT":
        log_handler = logging.StreamHandler(stream=sys.stdout)
    elif args.log == "STDERR":
        log_handler = logging.StreamHandler()
    else:
        log_handler = logging.handlers.RotatingFileHandler(args.log, maxBytes=4000)
    logger.addHandler(log_handler)

    log_level = getattr(logging, args.log_level)
    logger.setLevel(log_level)
    if log_level <= logging.DEBUG:
        logger.warn(
            "WARNING: Log level is %s, sensitive info may be logged!", args.log_level
        )

    authenticator = Authenticator(args.user_credentials)

    if not args.sender_blocklist:
        sender_blocklist = set()
    else:
        sender_blocklist = set(args.sender_blocklist.read_text().splitlines())

    if not args.sender_domain_blocklist:
        domain_blocklist = set()
    else:
        domain_blocklist = set(args.sender_domain_blocklist.read_text().splitlines())

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(args.cert, args.key)

    if args.local:
        if args.mboxdir is None and args.wmaildir is None:
            parser.error("--local requires --mboxdir or --wmaildir")
        elif args.mboxdir:
            logger.debug("Ensuring mbox path exists")
            args.mboxdir.mkdir(parents=True, exist_ok=True)
            handler = LocalMboxHandler(
                ok_domains=args.delivery_domain,
                mboxdir=args.mboxdir,
                authenticator=authenticator,
                domain_blocklist=domain_blocklist,
                sender_blocklist=sender_blocklist,
            )
        elif args.wmaildir:
            handler = LocalWMaildirHandler(
                ok_domains=args.delivery_domain,
                wmaildir=args.wmaildir,
                authenticator=authenticator,
                domain_blocklist=domain_blocklist,
                sender_blocklist=sender_blocklist,
            )

    controllers = []
    if args.forward:
        controllers.append(
            AuthController(
                ForwardingHandler(
                    ok_domains=args.forward_domain,
                    forward_host=args.forward_host,
                    forward_port=args.forward_port,
                    authenticator=authenticator,
                    domain_blocklist=domain_blocklist,
                    sender_blocklist=sender_blocklist,
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
                        authenticator=authenticator,
                        domain_blocklist=domain_blocklist,
                        sender_blocklist=sender_blocklist,
                    ),
                    port=args.ssl_port,
                    hostname=args.host,
                    starttls_context=context,
                    ssl_context=context,
                )
            )

    if args.local:
        logger.debug("Adding local AuthController")
        controllers.append(
            AuthController(
                handler,
                port=args.port,
                hostname="0.0.0.0",
                ssl_context=context,
                starttls_context=context,
            )
        )

    logger.warn(f"orouboros {__version__} staring with pid {os.getpid()}")
    for controller in controllers:
        logger.debug(f"starting controller {controller}")
        controller.start()

    if controllers:
        logger.info("Waiting for SIGINT or SIGQUIT")
        sig = signal.sigwait([signal.SIGINT, signal.SIGQUIT])
        logger.warn(f"{sig} caught, shutting down")
    else:
        print("Specify at least one of --forward or --local on the command line")

    for controller in controllers:
        logger.debug(f"stopping controller {controller}")
        controller.stop()


def deliver_maildir(msg, maildir, create=True):
    """
    Deliver an ``email.message.Message`` to the provided ``maildir``.

    If ``create`` (default: ``True``) is set, attempt to create the
    directory structure if it does not yet exist.
    """
    maildir = Path(maildir)
    tmpdir = maildir / "tmp"
    newdir = maildir / "new"
    tmpdir.mkdir(parents=True, exist_ok=True)
    newdir.mkdir(parents=True, exist_ok=True)
    msg_date = msg.get("Date")
    try:
        dt = email.utils.parsedate_to_datetime(msg_date)
    except TypeError:
        dt = datetime.now()
    written = False
    while not written:
        try:
            subject = re.sub("[^A-Za-z0-9]+", "-", msg.get("subject", ""))
            subject = subject.strip("-")
            tags = " ".join(sorted(msg.get("tags", [])))
            rand = base64.urlsafe_b64encode(os.urandom(5)).decode("utf-8")
            rand = rand.strip("=")
            filename = (
                f'{dt.strftime("%Y%m%d%H%M%S%f%z")}-{subject}-{rand}-[{tags}].eml'
            )
            tmpname = tmpdir / filename
            with tmpname.open("xb") as f:
                f.write(msg.as_bytes())

            filename = newdir / filename
            tmpname.rename(filename)
            written = True
        except FileExistsError:
            pass


if __name__ == "__main__":
    print("okay!")
