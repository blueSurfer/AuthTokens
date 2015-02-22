#!/usr/bin/env python
"""
Authentication tokens detection script.
"""

# -*- coding: utf-8 -*-
import signal
import argparse
import sqlite3
import os
import logging

from argparse import RawTextHelpFormatter
from authtokens.thirdparty.termcolor import colored
from selenium.common.exceptions import TimeoutException
from httplib import BadStatusLine, CannotSendRequest
from urllib2 import URLError
from authtokens.thirdparty.tldextract import TLDExtract
from authtokens import utils


__author__ = "Andrea Casini"
__license__ = "MIT"
__all__ = ["AuthenticationCrawler", "GhostCrawler"]
__version___ = '1.0.1'


# Logger setup.
FORMAT = '[%(levelname)s %(asctime)s] %(funcName)s: %(message)s'
formatter = logging.Formatter(FORMAT, datefmt='%H:%M:%S')
log = logging.getLogger('authtokenslog')
# Add console handler to print logs in stdout.
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)

# TldExtract logger setup.
tld_log = logging.getLogger('tldextract')
tld_log.addHandler(console_handler)
tld_log.setLevel(logging.CRITICAL)


def timeout_handler(s, f):
    raise TimeoutException


def main():

    description = """
    Detect Authentication Tokens

    What it does
    ------------
    1) Authenticates into given url(s);
    2) Collects cookies;
    3) Computes authentication token(s);
    4) Saves results into a SQlite3 database (see schema.sql).

    Usage example
    -------------
    > python detect_tokens.py  -i=http://example.com -m user@mail.com -u username -n nickname -p password
        --phantomjs /path/to/phantomjs

    """

    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=RawTextHelpFormatter)

    # Inputs
    group1 = parser.add_mutually_exclusive_group(required=True)

    group1.add_argument('-f',
                        dest='filename',
                        help="path to file containing a list of urls.",
                        type=argparse.FileType('rt'))

    group1.add_argument('-i',
                        dest='url',
                        help='input url',
                        type=str)

    parser.add_argument('-u',
                        dest='username',
                        help='your username',
                        type=str,
                        required=True)

    parser.add_argument('-m',
                        dest='email',
                        help='your email',
                        type=str)

    parser.add_argument('-n',
                        dest='nickname',
                        help='your nickname',
                        type=str)

    parser.add_argument('-p',
                        dest='password',
                        help='your password',
                        type=str)

    parser.add_argument('-d',
                        dest='database',
                        help='output database name in which results are stored',
                        type=str,
                        default='cookies.db')

    parser.add_argument('-t',
                        dest='thresh',
                        help='the authentication threshold',
                        type=float,
                        default=0.3)

    parser.add_argument('-k',
                        dest='maxtokens',
                        help='maximum number of authentication tokens to be found',
                        type=int,
                        default=None)

    parser.add_argument('--phantomjs',
                        dest='executable_path',
                        help='executable path to PhantomJS',
                        default=None,
                        type=str)

    parser.add_argument('--ignore-alarm',
                        dest='ignore',
                        help='skip any alerts dialog',
                        action='store_true',
                        default=False)

    parser.add_argument('--timeout',
                        dest='timeout',
                        help='maximum time to process a url',
                        type=int,
                        default=0)

    group = parser.add_argument_group('manual mode')

    group.add_argument('--manual',
                       dest='manual',
                       help='switch to manual login',
                       action='store_true',
                       default=False)

    group.add_argument('-s',
                       dest='timetologin',
                       help='time to wait for the user to login',
                       type=int,
                       default=30)

    try:
        args = parser.parse_args()
    except IOError, msg:
        parser.error(str(msg))
        return

    # Check if database already exists.
    db_is_new = not os.path.exists(args.database)

    # Open sqlite3 connection.
    with sqlite3.connect(args.database) as conn:

        if db_is_new:
            log.info('Creating schema.\n')
            with open('schema.sql', 'rt') as f:
                schema = f.read()
            conn.executescript(schema)
        else:
            log.info('Database exists, assume schema does, too.\n')

        cursor = conn.cursor()

        # !IMPORTANT Enable foreign key support.
        # This is necessary for the delete on cascade queries.
        cursor.execute("PRAGMA foreign_keys = ON")

        # Start Firefox.
        log.info('Starting Firefox.')
        firefox = utils.firefox_setup(args.email,
                                      args.username,
                                      args.nickname,
                                      args.password,
                                      args.ignore,
                                      args.thresh)

        # Start PhantomJS.
        log.info('Starting PhantomJS.\n')
        ghost = utils.phantomjs_setup(args.email,
                                      args.username,
                                      args.nickname,
                                      args.thresh,
                                      args.executable_path)

        # Split urls if a file is given.
        urls = args.filename.read().split('\n') if args.filename else [args.url]

        # Domain extractor (offline mode).
        extract = TLDExtract(fetch=False)

        for i, url in enumerate(urls):

            print('## PROCESSING URL {0} of {1}'.format(i + 1, len(urls)))

            if url.startswith('http://') or url.startswith('https://'):
                log.info(colored(url, 'blue'))

                # Clean up url from spaces.
                url = url.replace(' ', '')

                # Extract domain from url.
                domain = extract(url).domain
                log.info("Extracted domain: '{}'".format(domain))

                unique_cookies = []
                tokens = []

                # Errors.
                is_auth = False
                is_ambiguous = False

                # Start a global timer.
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(args.timeout)

                try:

                    # Ambiguity check.
                    if not firefox.is_authenticated(url):
                        if not args.manual:
                            log.info(colored('Automatic Mode Active\n', 'magenta'))
                            is_auth = firefox.authenticate(firefox.current_url)
                        else:
                            log.info(colored('Manual Mode Active', 'magenta'))
                            utils.start_timer(args.timetologin)
                            is_auth = firefox.is_authenticated(firefox.current_url)

                    else:
                        log.critical(colored('Page is ambiguos!\n', 'red'))
                        is_ambiguous = True

                    if is_auth and not is_ambiguous:

                        log.info(colored('Login successful!\n', 'green'))

                        # Get current url post authentication.
                        post_auth_url = firefox.current_url
                        cookies = firefox.get_cookies()

                        # !IMPORTANT Remove cookies duplicates to
                        # prevent unexpected behaviour in our
                        # detection method (see cookies policy).
                        unique_cookies = utils.delete_duplicates_cookies(cookies)

                        log.info('{} cookies collected. Detecting authentication tokens.\n'.format(len(unique_cookies)))

                        # Use the ghost to find authentication tokens.
                        tokens = ghost.detect_authentication_tokens(
                            post_auth_url,
                            unique_cookies,
                            max_tokens=args.maxtokens)
                    else:
                        log.info(colored('Login failed!\n', 'red'))

                except (URLError, CannotSendRequest):
                    log.warning(colored('Connection error!\n', 'red'))

                except TimeoutException:
                    log.warning(colored('Operation timed out!\n', 'red'))

                except BadStatusLine:
                    log.warning(colored('Browser quits unexpectedly!\n', 'red'))

                finally:
                    # Reset timer.
                    signal.alarm(0)

                has_failed = not tokens

                # If the analysis has failed do not save any cookies..
                if has_failed:
                    unique_cookies = []

                # Create website entry.
                website = [domain, url, has_failed]

                # Save results into database.
                utils.add_entry(cursor, website, unique_cookies, tokens)

                # Commit changes.
                conn.commit()

            else:
                log.info("Url '{}' is not valid\n".format(url))

    # Quit browsers.
    log.info('Quitting browsers.')
    firefox.quit()
    ghost.quit()


if __name__ == '__main__':
    main()
