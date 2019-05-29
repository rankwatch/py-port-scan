import argparse
import sys
import os

sys.path.insert(0, "PortScanner/")

from port_scanner import MultiScan


def main():
    parser = argparse.ArgumentParser()

    threads = 100
    timeout = 2

    parser.add_argument("target_ips", help="Target IPs", type=str)
    parser.add_argument("min_port", help="Port", type=int)
    parser.add_argument("max_port", help="Port", type=int)
    parser.add_argument("--threads", help="Max Numbers Of Threads", type=int)
    parser.add_argument("--timeout", help="Max Timeout For Socket", type=int)
    parser.add_argument("--proxy_ips", help="Two Proxy Ips", type=str)
    parser.add_argument("--proxy_ports", help="Two open ports of Proxy ips",
                        type=str)
    parser.add_argument("operation", help="Operations", type=str)

    args = parser.parse_args()

    ports = range(args.min_port, args.max_port)
    target_ips = args.target_ips.split(",")

    if args.threads:
        threads = int(args.threads)

    if args.timeout:
        timeout = int(args.timeout)

    if args.proxy_ips and args.proxy_ports:
        proxy_ips = args.proxy_ips.split(",")
        proxy_ports = [int(x) for x in args.proxy_ports.split(",")]

    if args.operation == "fullscan":

        print("Full Scan :")
        mulscan = MultiScan(target_ips, ports, threads, timeout)
        print(mulscan.run_full_scan())

    elif args.operation == "proxyscan":

        if len(proxy_ips) == 2 and len(proxy_ports) == 2:
            print("Proxy Scan :")
            mulscan = MultiScan(target_ips, ports, threads,
                                timeout, proxy_ips, proxy_ports)
            print(mulscan.run_proxy_scan(True))
            print(mulscan.run_proxy_scan(False))
        else:
            print("Proper arguments not supplied")


main()
