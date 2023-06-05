from setuptools import setup, find_packages

setup(
    name='sightql',
    version='1.0.0',
    author='Ruulian',
    author_email='ruulian@protonmail.com',
    description='SightQL is a Python library which allows to exploit an SQL Injection using multiple entrypoints such as classical GET/POST parameters and cookies.',
    packages=find_packages(),
    install_requires=[
        'pwntools'
    ],
)