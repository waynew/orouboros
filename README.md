# Orouboros

This is a mailserver designed to violate all kinds of standards, with the
express goal of making it more useful for running your own mailserver.
Specifically, it's designed to work as a limited relay server.

It's definitely not complete yet, but it's somewhat functional. It will be
complete when it can operate like this for you:


    (some local server) <---> (some cloud VPS or something) <---> (internet)


But like this for everyone on the Internet;

    (some local server) <--- (some cloud VPS or something) <--- (internet)

In other words, for anyone who does not have the correct credentials
configured, email should only be deliverable to your local server via the
publically accessible VPS (or something).

This is for folks who either a) have horrible ISPs who won't give them port 25
inbound, or b) just want to not expose their home IPs to the Internet, at least
generally speaking.

So, that's the goal.

# Hacking

This isn't complete yet. For the most part... good luck!

To generate a self-signed cert for playing around:

    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout server.key -out server.crt -subj "/CN=localhost/OU=testing"

Now `python -m pip install -e .` should get you a devel version installed in
your venv (you did create one, right?)

You'll need a credentials file (asdf/asdf is this user/pass):

    echo '{"asdf": {"salt": "dExNPiUB4fBd39dXxiGLvA==", "hash": "Ow5nPPcyWgy11lUmF/rK45aReQVTMXsiJ237PZKmbBk="}}' > creds.json

Then you should be able to start it up:

    orouboros --cert server.crt --key server.key --forward-domain example.com --delivery-domain example.com --local --mboxdir /tmp/mail --port 2255 --log STDERR --log-level DEBUG

Now connect via openssl:

    openssl s_client -connect localhost:2255 -crlf   # skip crlf on Windows

Now you can send an email:

    EHLO asdf
    AUTH PLAIN
    YXNkZgBhc2Rm
    MAIL FROM: test@example.com
    rcpt to: another_test@example.com
    DATA
    From: whoever@wherever.com
    To: anyone@example.net
    Subject: Testing

    This is a test
    .

The server should reply a bunch in between those. With openssl `rcpt to` has to
be lowercase, because otherwise it will try and renegotiate the SSL connection
which is... unexpected.

Anyway... this definitely isn't intended for general consumption - use it if
you will, and feel free to open a PR if you find/fix a bug! Otherwise, this is
provided as-is. I will mostly just be making adjustments to suit my own needs!
