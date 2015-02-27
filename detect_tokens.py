#!/usr/bin/env python
"""
Authentication tokens detection script.
"""

# -*- coding: utf-8 -*-
import signal
import argparse
import logging

from argparse import RawTextHelpFormatter
from selenium.common.exceptions import TimeoutException
from httplib import BadStatusLine, CannotSendRequest
from urllib2 import URLError

from authtokens.thirdparty.termcolor import colored
from authtokens import crawler


__author__ = "Andrea Casini"
__license__ = "MIT"
__all__ = ["AuthenticationCrawler", "GhostCrawler"]
__version___ = '1.0.1'


PAGE_LOAD_TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:28.0) Gecko/20100101 Firefox/28.0"


# Logger setup.
FORMAT = '[%(levelname)s %(asctime)s] %(funcName)s: %(message)s'
formatter = logging.Formatter(FORMAT, datefmt='%H:%M:%S')
log = logging.getLogger('authtokenslog')
# Add console handler to print logs in stdout.
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
log.addHandler(console_handler)
log.setLevel(logging.DEBUG)


def timeout_handler(s, f):
    raise TimeoutException


def firefox_setup(email,
                  username,
                  nickname,
                  password,
                  ignore_alerts=False,
                  auth_thresh=.3):
    """Start Firefox and setup preferences. """

    # Firefox preferences.
    prefs = [('intl.accept_languages', 'en'),        # set default language to english
             ('general.useragent.locale', 'en-US')]  # set user current locale

    firefox = crawler.AuthenticationCrawler(email=email,
                                            username=username,
                                            nickname=nickname,
                                            password=password,
                                            preferences=prefs,
                                            ignore_alerts=ignore_alerts,
                                            auth_thresh=auth_thresh)

    firefox.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return firefox


def phantomjs_setup(email, username, nickname, auth_thresh=.3, executable_path=None):
    """Start PhantomJS and setup extensions and preferences. """

    # PhantomJS preferences.
    service_args = ['--ssl-protocol=any',
                    '--ignore-ssl-errors=true']

    # Change PhantomJS user agent to improve sites compatibility.
    capabilities = {"phantomjs.page.settings.userAgent": USER_AGENT}

    ghost = crawler.GhostCrawler(email=email,
                                 username=username,
                                 nickname=nickname,
                                 service_args=service_args,
                                 capabilities=capabilities,
                                 executable_path=executable_path,
                                 auth_thresh=auth_thresh)

    ghost.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return ghost


def delete_duplicates_cookies(cookies):
    """Delete cookies with same name."""
    unique_cookies = []
    seen = set()
    for ck in cookies:
        if ck['name'] in seen:
            log.info('Deleting duplicate cookie: %s' % ck['name'])
        else:
            seen.add(ck['name'])
            unique_cookies.append(ck)
    return unique_cookies


def main():

    description = """
    Detect Authentication Tokens

    What it does
    ------------
    1) Authenticates into given url;
    2) Collects cookies;
    3) Computes authentication token(s).

    Usage example
    -------------
    > python detect_tokens.py  -i=http://example.com -m user@mail.com -u username -n nickname -p password
        --phantomjs /path/to/phantomjs

    """

    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=RawTextHelpFormatter)

    parser.add_argument('-i',
                        dest='url',
                        help='input url',
                        type=str,
                        required=True)

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
                        dest='path',
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

    parser.add_argument('--manual',
                        dest='manual',
                        help='switch to manual login',
                        action='store_true',
                        default=False)

    try:
        args = parser.parse_args()
    except IOError, msg:
        parser.error(str(msg))
        return

    url = args.url

    if not url.startswith('http://') and not url.startswith('https://'):
        log.info("Url '" + colored(url, 'blue') + "' is not valid\n".format(url))
        return

    # Start Firefox.
    log.info('Starting Firefox')
    firefox = firefox_setup(args.email,
                                  args.username,
                                  args.nickname,
                                  args.password,
                                  args.ignore,
                                  args.thresh)

    # Start PhantomJS.
    log.info('Starting PhantomJS\n')
    ghost = phantomjs_setup(args.email,
                                  args.username,
                                  args.nickname,
                                  args.thresh,
                                  args.path)

    unique_cookies = []
    tokens = []

    try:

        log.info('Processing ' + colored(url, 'blue'))

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
                    log.info(colored('Mode: automatic', attrs=['underline']))
                    is_auth = firefox.authenticate(firefox.current_url)
                else:
                    log.info(colored('Mode: manual', attrs=['underline']))
                    raw_input("Press Enter to continue...")
                    is_auth = firefox.is_authenticated(firefox.current_url)

            else:
                log.critical(colored('Page is ambiguos!\n', 'red'))
                is_ambiguous = True

            if is_auth and not is_ambiguous:

                log.info(colored('Login successful!\n', 'green'))

                # Get post authentication url and retrieve 
                # authentication cookies.
                post_auth_url = firefox.current_url
                cookies = firefox.get_cookies()

                # Remove cookies duplicates to prevent unexpected behaviour 
                # in our detection method (see cookies policy).
                unique_cookies = delete_duplicates_cookies(cookies)

                log.info('{} cookies collected. Detecting authentication tokens\n'.format(len(unique_cookies)))

                # Use PhantomJS to find authentication tokens.
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

    finally:

        # Quit browsers.
        log.info('Quitting browsers.')
        firefox.quit()
        ghost.quit()

    return tokens


if __name__ == '__main__':
    main()
