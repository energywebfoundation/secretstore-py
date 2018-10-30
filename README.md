# Secret Store python package
This is a python library for interacting with Parity's secret store.
It is an abstraction layer (API) on top of the official 
[secretstore module RPC API](https://wiki.parity.io/JSONRPC-secretstore-module) and
[secretstore sessions](https://wiki.parity.io/Secret-Store).
Naming conventions follow the underlying APIs'.

The documentation is for this library and its functions. For more information on 
how Secret Store works, please refer to the [Parity wiki](https://github.com/paritytech/wiki). 
Most of the function descriptions have been copied from there.

## Maintainers
**Primary**: Adam Nagy (@ngyam)

## Documentation

[![Documentation Status](https://readthedocs.org/projects/secretstore/badge/?version=latest)](https://secretstore.readthedocs.io/?badge=latest)

Readthedocs: https://secretstore.readthedocs.io/index.html

## Quickstart

```bash
pip install secretstore
```

Then in your project:

```python
from web3 import Web3, HTTPProvider
from secretstore import SecretStore


web3 = Web3(HTTPProvider("http://127.0.0.1:8545"))

# endpoint exposed by your Secret Store
ss = SecretStore(web3, "http://127.0.0.1:8090")

# secretstore API calls
ss.something..

# secretstore session calls
ss.session.something..

```

If you wonder how to set up a Secret Store cluster, check out the official [config guide](https://wiki.parity.io/Secret-Store-Configuration) and peek into the [nodes_ss_dev/](./nodes_ss_dev/) folder.

## Examples

You can see some examples amongst the [tests](tests/test_secretstore.py).

## Contributing

Please read [contributing](./CONTRIBUTING.md) and our [code of conduct](./CODE_OF_CONDUCT.md) for details.

## Getting started (as a dev)

### Prerequisites

 - Python 3.5+

### Installing

```
git clone https://github.com/energywebfoundation/secretstore-py.git
pip install -e .[dev]
```

## Running the tests

**ACHTUNG**: make sure to start the local secret store cluster first.

1. start nodes

``` bash
cd nodes_ss_dev
./start.sh
```

2. run tests 

```bash
cd tests
python3 -m unittest
```

3. When done fiddling around:

```bash
cd nodes_ss_dev && ./stop.sh
```


## Versioning

We use [SemVer](http://semver.org/) for versioning. Version number is bumped with `bumpversion` tool.

## License

This project is licensed under the GPLv3 License - see the [LICENSE](./LICENSE) file for details.

## Acknowledgments

* Special thanks to Parity
