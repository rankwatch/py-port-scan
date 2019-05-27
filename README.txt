==================
RW Py-Port-Scanner
==================

Port Scanner allows you to scan port range for any IP Address.

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


