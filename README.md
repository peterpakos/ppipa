# ppipa
PP's FreeIPA Module

PyPI package: [ppipa](https://pypi.python.org/pypi/ppipa)

If you spot any problems or have any improvement ideas then feel free to open
an issue and I will be glad to look into it for you.

## Installation
A recommended way of installing the tool is pip install.

### pip install
The tool is available in PyPI and can be installed using pip:
```
$ pip install --user ppipa
```

## Usage
```
from ppipa import FreeIPAServer

ipa = FreeIPAServer(host='ipa01.example.com', bindpw='password')
```