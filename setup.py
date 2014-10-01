try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name='AuthTokens',
    version='1.0.0',
    author='Andrea Casini',
    author_email='andreacasini88@gmail.com',
    packages=['authtokens'],
    license='MIT',
    description='A Selenium-based authentication token detector',
    long_description=open('README.md').read(),
    install_requires=['selenium >= 2.42',
                      'beautifulsoup4',
                      'termcolor',
                      'tldextract'])
