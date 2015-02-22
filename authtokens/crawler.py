#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Selenium-based crawlers library."""
from __future__ import division

import string
import getpass
import logging

from itertools import combinations
from time import sleep

from thirdparty.termcolor import colored
from bs4 import BeautifulSoup

from selenium.webdriver import Firefox, FirefoxProfile, PhantomJS
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import (StaleElementReferenceException,
                                        NoSuchFrameException,
                                        NoAlertPresentException,
                                        WebDriverException)

import re


__author__ = "Andrea Casini"
__license__ = "MIT"
__all__ = ["AuthenticationCrawler", "GhostCrawler"]
__version___ = '1.0.0'


# Time to wait for the website to respond (in seconds).
TIME_TO_WAIT = 5

# Some useful xPaths.
PASSWORD_TYPE = ".//input[@type='password']"
LOGIN_TYPE = ".//input[@type='text'] | .//input[@type='email']"

# List of known login words.
LOGIN_WORDS = ['log\s?in',
               'sign\s?in',
               'entra',
               'accedi',
               'accesso',
               'connetti',
               'connettiti',
               'connessione']

# List of known logout words.
LOGOUT_WORDS = ['log\s?out',
                'sign\s?out',
                'my\s?account',
                'esci',
                'disconnetti',
                'disconnettiti',
                'disconnessione']

# List of known socials.
SOCIALS = ['facebook', 'google', 'twitter']

# List of cookies to be skipped in the tokens detection.
SKIPPED_COOKIES = ['__utma',
                   '__utmv',
                   '__utmz',
                   '__utmc',
                   '__utmb',
                   '__utmt',
                   '__gads',
                   '_ga']

# Compiled regular expressions.
LOGIN_RE = re.compile('|'.join('.*(^|\s+)%s(\s+|$).*' % w for w in LOGIN_WORDS), re.I | re.S)
LOGOUT_RE = re.compile('|'.join('.*(^|\s+)%s(\s+|$).*' % w for w in LOGOUT_WORDS), re.I | re.S)

# Get global logger.
log = logging.getLogger('authtokenslog')


class AuthenticationCrawler(Firefox):
    """A Firefox-based automation tool to authenticate in a website.

    Parameters
    ----------
    email : string
        The user's email to log in with.

    username : string
        The user's username to log in with.

    nickname : string
        The user's nickname.

    password : string
        The user's password.

    preferences : list of tuple (default None)
        List of preferences elements of shape <pref, value> each.
        Check out 'about:config' in Firefox browser to setup your preferences.

    extensions : list of string (default None)
        List of string paths to a firefox '.xpi' file.

    ignore_alerts : boolean (default False)
        If True every alert dialog will be always accepted (EXPERIMENTAL).

    auth_thresh : float
        The authentication threshold used in the 'is_authenticated' method.

    """

    def __init__(self,
                 username,
                 email='',
                 password='',
                 nickname='',
                 auth_thresh=0.5,
                 preferences=None,
                 extensions=None,
                 ignore_alerts=False):

        self.email = email
        self.username = username
        self.nickname = nickname
        self.password = password
        self.preferences = preferences
        self.extensions = extensions
        self.ignore_alerts = ignore_alerts
        self.auth_thresh = auth_thresh

        # Start Firefox with custom profile.
        super(AuthenticationCrawler, self).__init__(
            firefox_profile=self.setup_firefox_profile())

    def restart(self):
        """Restart browser."""
        self.quit()

        log.info('Restarting Firefox.')
        super(AuthenticationCrawler, self).__init__(
            firefox_profile=self.setup_firefox_profile())

    def setup_firefox_profile(self):
        """Return a custom firefox profile with given preferences
        and extensions.

        """
        fp = FirefoxProfile()

        if self.extensions:
            # Load extensions.
            for ext in self.extensions:
                fp.add_extension(ext)

        if self.preferences:
            # Load preferences
            for key, value in self.preferences:
                fp.set_preference(key, value)

        return fp

    def handle_modal_dialog(self):
        """Move focus to the current frame if present."""
        try:
            self.switch_to.frame(self.switch_to.active_element)
        except NoSuchFrameException:
            log.info('No frame found!')

    def handle_alert(self):
        """Accept alert dialog."""
        try:
            alert = self.switch_to.alert
            alert.accept()
        except NoAlertPresentException:
            log.info('No alert present!')

    def search_login_form(self, url):
        """Search a login form by scraping the page clicking on
        any login-matching links/buttons.

        Returns
        -------
        login_field : selenium.WebElement
            The login filed in which to type your login credentials.

        password_field : selenium.WebElement
            The password in which to type the password.

        """

        # Matches a link or a button.
        xpath = '//a | //button'
        links_and_buttons = self.find_elements_by_xpath(xpath)

        for i in xrange(len(links_and_buttons)):
            try:
                if links_and_buttons[i]:

                    text = links_and_buttons[i].text

                    if LOGIN_RE.match(text) and any(w not in text.lower() for w in SOCIALS):
                        log.info(u"Clicking on '{}'".format(text))
                        links_and_buttons[i].click()

                        # Wait for a page change.
                        sleep(TIME_TO_WAIT)

                        self.handle_modal_dialog()

                        # Get a login form from the changed page.
                        login_field, pwd_field = self.get_login_form()

                        if pwd_field:
                            return login_field, pwd_field

                        # Go back to home url.
                        self.get(url)

                        # Reload elements.
                        links_and_buttons = self.find_elements_by_xpath(xpath)

            except (StaleElementReferenceException,
                    WebDriverException,
                    IndexError):
                log.info('Element not found. Page has changed')
                break

        # Return first visible password input type element if it exist.
        for pwd_field in self.find_elements_by_xpath(PASSWORD_TYPE):
            if pwd_field.is_displayed():
                return None, pwd_field

        return None, None

    def get_login_form(self):
        """A login form is a form with exactly one password input field
        and exactly one login input field.

        Returns
        -------
        login_field : WebElement
            The login input field.

        password_field : WebElement
            The password input field.

        """
        forms = self.find_elements_by_tag_name('form')

        for form in forms:

            try:

                # Get password and text/mail fields of this form.
                login_fields = form.find_elements_by_xpath(LOGIN_TYPE)
                pwd_fields = form.find_elements_by_xpath(PASSWORD_TYPE)

                if pwd_fields:

                    # Consider visible fields only.
                    displayed_login_fields = [l for l in login_fields if l.is_displayed()]
                    displayed_pwd_fields = [p for p in pwd_fields if p.is_displayed()]

                    # Is this a login form?
                    if len(displayed_pwd_fields) == 1 and len(displayed_login_fields) == 1:
                        return displayed_login_fields[0], displayed_pwd_fields[0]

            except StaleElementReferenceException:
                log.info('Form not found. Page has changed.')

        return None, None

    def fill_login_form(self, url, login):
        """Types 'login' and 'password' into a login form."""

        login_field, pwd_field = self.get_login_form()

        if not pwd_field:
            log.info('Searching a login form.')
            login_field, pwd_field = self.search_login_form(url)

            if not pwd_field:
                log.critical('No login form found.')
                return

        # Clear any text in the password field.
        pwd_field.clear()
        log.info('Filling login form.')

        if not self.password:
            self.password = getpass.unix_getpass('\nPlease enter your password: ')

        if login_field:
            pwd_field.send_keys(self.password)
        else:
            # Attempt to locate login field by hitting SHIFT + TAB
            pwd_field.send_keys(self.password, Keys.SHIFT, Keys.TAB)
            login_field = self.switch_to.active_element

        login_field.clear()
        login_field.send_keys(login, Keys.RETURN)

        # Wait for page to respond to the submit.
        sleep(TIME_TO_WAIT)

    def authentication_score(self, url):
        """Performs a series of heuristic tests on the current url and
        calculates a probability of being authenticated.

        Returns
        -------
        auth_score : float [0, 1]
            The authentication score.

        """

        self.get(url)

        soup = BeautifulSoup(self.page_source, 'html.parser')

        def is_visible(element):
            if element.parent.name in ['style', '[document]', 'head', 'title'] \
                    or re.match(r'<!--.*-->', text.encode('utf-8')):
                return False
            return True

        tests = {'no-login': True, 'logout': False, 'email': False, 'user': False, 'nick': False}

        for text in soup.find_all(text=True):
            if not text.isspace() and is_visible(text):
                if LOGIN_RE.match(text):
                    log.info("Login found")
                    tests['no-login'] = False
                elif LOGOUT_RE.match(text):
                    log.info("Logout found")
                    tests['logout'] = True
                elif self.email and self.email in text.lower():
                    log.info("Email found")
                    tests['email'] = True
                elif self.username and self.username in text.lower():
                    log.info("Username found")
                    tests['user'] = True
                elif self.nickname and self.nickname in text.lower():
                    log.info("Nickname found")
                    tests['nick'] = True

        if tests['no-login']:
            log.info('No login found')

        number_of_tests = len(tests) - (not self.username) - (not self.email) - (not self.nickname)
        return sum(tests.values()) / number_of_tests

    def is_authenticated(self, url):
        """Threshold the authentication score."""
        auth_score = self.authentication_score(url)
        log.info('Probability: %.2f' % auth_score)
        return auth_score > self.auth_thresh

    def authenticate(self, url):
        """Use credentials to login into a website given its url.

        Inputs
        ------
        url : string
            the url of the website to authenticate in.

        Returns
        -------
        boolean : True,  if authentication succeed
                  False, otherwise

        """

        if self.username:
            log.info('Log in with username.')
            self.fill_login_form(url, self.username)
            if self.is_authenticated(self.current_url):
                return True

        if self.email:
            log.info('Log in with email.')
            self.delete_all_cookies()
            self.fill_login_form(url, self.email)

        return self.is_authenticated(self.current_url)


class GhostCrawler(PhantomJS, AuthenticationCrawler):
    """A PhantomJS-based automation tool used to perform cookies' analysis.

    PhantomJS is a headless WebKit scriptable with a JavaScript API.
    It has **fast** and **native** support for various web standards:
    DOM handling, CSS selector, JSON, Canvas, and SVG,

    Parameters
    ----------
    email : string
        The user's email used to log in.

    username : string
        The user's username used to log in.

    nickname : string
        The user's nickname.

    service_args : list of string (default None)
        List of PhantomJS switches.

    auth_thresh : float
        Threshold to be compared with the authentication score to
        decide whether or not the user is authenticated.

    """

    def __init__(self,
                 username,
                 email='',
                 password='',
                 nickname='',
                 ignore_alerts=False,
                 auth_thresh=.3,
                 service_args=None,
                 capabilities=dict(),
                 executable_path=None):

        self.email = email
        self.username = username
        self.nickname = nickname
        self.password = password
        self.ignore_alerts = ignore_alerts
        self.auth_thresh = auth_thresh

        # PhantomJS settings.
        self.capabilities = capabilities
        self.service_args = service_args
        self.executable_path = executable_path

        super(GhostCrawler, self).__init__(
            executable_path=self.executable_path,
            desired_capabilities=dict(self.capabilities),
            service_args=list(self.service_args))

    def restart(self):
        """Restart browser (used to clean session)."""

        self.quit()

        log.info('Restarting PhantomJS.')
        super(GhostCrawler, self).__init__(
            executable_path=self.executable_path,
            desired_capabilities=dict(self.capabilities),
            service_args=list(self.service_args))

    def handle_alert(self):
        """Accept alert dialog."""
        self.execute_script("window.alert = function(){}")

    def set_cookies(self, cookies):
        """Add a set of cookies to the current domain and delete
        all other cookies.

        """
        self.delete_all_cookies()

        for ck in cookies:
            try:
                self.add_cookie(ck)
            except WebDriverException:
                log.warning("Different domain error.")
                dom = ck['domain']
                ck['domain'] = ''
                self.add_cookie(ck)
                ck['domain'] = dom

    def exhaustive_search_authentication_tokens(self,
                                                url,
                                                cookies,
                                                max_tokens=None,
                                                intersect=frozenset()):
        """Enumerate all possible combinations of cookies (power-set) and
        find which of them is an authentication token. This exploit the
        minimality condition and the intersection inclusion of the
        authentication tokens to reduce the search space.

        WARNING: worst case time complexity is O(2^n)
        where n is the number of cookies.

        """

        if not max_tokens:
            max_tokens = len(cookies)

        tokens = []

        # Initial number of element for each combination.
        k = max(1, len(intersect))

        # Get cookies names and filters out GA cookies.
        names = frozenset(ck['name'] for ck in cookies
                          if (ck['name'] not in SKIPPED_COOKIES))

        # Explore power set (consider all possible combinations).
        while k < len(names) and len(tokens) < max_tokens:

            # Compute combinations n choose k of cookies.
            candidates = [frozenset(comb) for comb in combinations(names, k)]

            log.info('Searching over {} combinations with {} element.'.format(
                len(candidates), k))

            for i, cand in enumerate(candidates):

                # Check tokens containing the intersection set.
                contains_intersect = cand >= intersect
                # Check for minimality condition.
                is_minimal = not any(cand >= set(t) for t in tokens)

                if contains_intersect and is_minimal:

                    log.info('Set n. {} of {}: {}'.format(
                        i + 1,
                        len(candidates),
                        list(cand)))

                    # Add cookies subset.
                    self.set_cookies(c for c in cookies if c['name'] in cand)

                    # Check if such subset actually authenticates you.
                    if self.is_authenticated(url):
                        log.info(colored('LOGGED IN', 'green'))
                        tokens.append(list(cand))

                        # Clean session.
                        self.restart()
                        self.get(url)

                else:

                    log.info('Set n. {} of {}: {} | SKIPPED!'.format(
                        i + 1,
                        len(candidates),
                        list(cand)))

                if len(tokens) >= max_tokens:
                    break

            k += 1

        log.info(colored('Found {} authentication tokens: {}\n'.format(
            len(tokens), tokens), attrs=['bold']))

        return tokens

    def build_intersection(self, url, cookies):
        """Search for the elements in common (i.e. the intersection)
        of multiple authentication tokens.

        """
        intersect = []

        for i, ck in enumerate(cookies):

            log.info("Deleting cookie ({} of {}): '{}'".format(
                i + 1, len(cookies), ck['name']))

            if ck['name'] not in SKIPPED_COOKIES:

                # Use a buffer and remove the cookie.
                buff = list(cookies)
                buff.remove(ck)
                self.set_cookies(buff)

                # Do we break the session by removing this cookie?
                if not self.is_authenticated(url):
                    log.info(colored('SESSION BROKEN', 'red'))
                    intersect.append(ck['name'])

            else:
                log.info("Skipped!")

        log.info(colored('Intersection found: {}\n'.format(list(intersect)),
                         attrs=['bold']))

        return intersect

    def detect_authentication_tokens(self, url, cookies, max_tokens=None):
        """Return a list of authentication tokens.

        An authentication token is a minimal set of authentication cookies
        which allows the server to authenticate the client, restoring
        the state of the associated user without asking her to log in.

        Inputs
        ------
        url : string
            the url of the website to analyze.

        cookies : list of dictionaries
            the list of cookies by which the user is authenticated.

        max_tokens : int (default:None)
            the maximum number of tokens to look for.

        Returns
        -------
        tokens : list of list
            the list of cookies names belonging to
            each authentication token.

        """

        tokens = []

        log.info(colored(url, 'blue'))
        log.info('Checking input cookies.')

        self.get(url)
        self.set_cookies(cookies)

        # Input cookies check.
        if not self.is_authenticated(url):
            log.critical(colored('Login failed.\n', 'red'))
            return tokens

        intersect = self.build_intersection(url, cookies)

        # Clean up session.
        self.restart()
        self.get(url)

        if intersect:
            log.info('Checking if {} is the unique authentication token.'.format(intersect))
            self.set_cookies([c for c in cookies if c['name'] in intersect])

            if self.is_authenticated(url):
                log.info(colored('Found unique authentication token: {}\n'.format(
                    intersect), attrs=['bold']))
                return [intersect]

        log.warning('Multiple authentication tokens.')
        tokens = self.exhaustive_search_authentication_tokens(
            url,
            cookies,
            max_tokens,
            intersect=frozenset(intersect))

        return tokens
