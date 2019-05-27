# Port Scanner

Port Scanner is a python library to scan the mentioned ports of the given IP address.

## Python Version

This library is built on Python 3.7

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the Port Scanner.

```bash
pip install PortScanner
```

## Usage

```python
import PortScanner

mulScan = PortScanner.MultiScan(
        targets=["List of target IPs"],
        ports=["List of ports to scan"],
        threads=100, # Number of threads in the thread pool
        timeout=1, # Seconds to socket timeout
        proxy_ip=["List of Proxy IPs"],
        proxy_port=["List of proxy ports"]
)

# To Scan all the ports ie 0-65535 for the given targets
scan_result = mulScan.run_full_scan()

# To scan the given ports via a secure and unsecure proxy server
proxy_scan_result = mulScan.run_proxy_scan()
```


##### ToDo
- [ ] CLI executable script
- [x] Adding README.txt (reST) for PyPi Page
- [ ] Bulding doc for PyPi and Git
- [ ] Specifying [Entry points](https://the-hitchhikers-guide-to-packaging.readthedocs.io/en/latest/creation.html#entry-points) for a standalone application
- [ ] While reusing the same object a lot of values may be static.  


## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate

## License
[GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)
