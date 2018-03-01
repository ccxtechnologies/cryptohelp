#!/usr/bin/python

from setuptools import setup
from setuptools import find_packages

__module__ = 'cryptohelp'
__url__ = 'https://github.com/ccxtechnologies'

__version__ = None
exec(open(f'{__module__}/__version__.py').read())

setup(
        name=__module__,
        version=__version__,
        author='CCX Technologies',
        author_email='charles@ccxtechnologies.com',
        description='crypto helper library',
        license='MIT',
        url=f'{__url__}/{__module__}',
        download_url=f'{__url__}/archive/v{__version__}.tar.gz',
        python_requires='>=3.6',
        packages=find_packages(),
        install_requires=[
                'pynacl>=1.1.2',
                'cryptography>=2.0.3',
        ],
)
