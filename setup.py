import os
from setuptools import setup, find_packages

__version__ = '0.1.0'

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


install_requires = [
    'aiosmtpd',
]
setup(
    name='orouboros',
    version=__version__,
    author='Wayne Werner',
    author_email='waynejwerner@gmail.com',
    url='TODO',
    #long_description=read('README.rst'),
    py_modules=['orouboros'],
    entry_points = {
        'console_scripts': [
            'orouboros=orouboros:run',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        # TODO: Add other trove classifiers -W. Werner, 2017-10-04
        'Topic :: Office/Business',
        'Topic :: Utilities',
    ],
)
