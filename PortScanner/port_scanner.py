import time
import socket
import logging
import multiprocessing
import configparser
import socks

from queue import Queue
from threading import Thread
from multiprocessing import Process, cpu_count


class Worker(Thread):
    def __init__(self, tasks: Queue):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                print(e)
            finally:
                self.tasks.task_done()


class ThreadPool:
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        self.tasks.put((func, args, kargs))

    def map(self, func, args_list):
        for args in args_list:
            self.add_task(func, args)

    def wait_completion(self):
        self.tasks.join()


class Scan:

    """

        Scan class that creates threads and scans a single IP
        for the given list of ports.

        Arguments:

            target: string - IP Address to scan the ports
            ports: list - List of ports to scan
            threads: int - Number of threads to use
            timeout: int - Socket connection timeout in seconds
            proxy_ip: list - The proxy IPs to use
            proxy_port: list - Proxy port to use

        Example:

            scan = Scan(target="192.168.1.0",
                        ports=range(65536),
                        threads=200,
                        timeout=2)
            scan.run()

    """

    def __init__(self, target: str, ports: list, threads: int=100,
                 timeout: int=3, proxy_ip: list=["127.0.0.1"],
                 proxy_port: list=[80]):

        self.target = target
        self.no_of_threads = threads
        self.ports = ports
        self.timeout = timeout
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port

        self.closed = 0
        self.opened = 0
        self.open_ports = []
        self.closed_ports = []

        self.runtime = 0

    def pscan(self, port: int):

        """

            Port scanning using socket connection. If exception
            occurs hence the port is closed else it is open.

            Arguments:

                port: int - Port to try connecting to

            Example:

                pscan(3345)

        """

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            con = s.connect((self.target, port))

            self.opened += 1
            self.open_ports.append(port)

        except Exception as e:
            self.closed += 1
            self.closed_ports.append(port)

    def proxy_scan(self, port: int):
        
        try:

            s = socks.socksocket()
            s.settimeout(self.timeout)

            s.set_proxy(socks.PROXY_TYPE_SOCKS5,
                        self.proxy_ip, self.proxy_port,
                        True)
            
            s.connect((self.target, port))
            
            self.opened += 1
            self.open_ports.append(port)

        except:

            self.closed += 1
            self.closed_ports.append(port)
        
        finally:

            s.close()

    def get_info(self) -> dict:

        """
            Return the class variables essential after the scanning

            Return Values:

                Number of open ports
                Number of closed ports
                List of open ports
                List of closed ports
                Runtime of scan
        """
        return {"Number of Open Ports": self.opened, 
                "Number of Closed Ports": self.closed,
                "Opened Ports": self.open_ports,
                "Closed Ports": self.closed_ports,
                "Runtime": self.runtime}

    def run(self, log: dict):

        """

            Executes the scan after creating a threadpool and
            also stores and calculates the runtime.

            Arguments:

                log: dict - The shared dictionary among all the threads

        """

        self.runtime = time.time()
        pool = ThreadPool(self.no_of_threads)

        pool.map(self.pscan, self.ports)
        pool.wait_completion()

        self.runtime = time.time() - self.runtime

        log[self.target] = self.get_info()

    def run(self, proxy_log: dict, flag: bool=True):

        self.runtime = time.time()
        pool = ThreadPool(self.no_of_threads)

        pool.map(self.proxy_scan, self.ports)
        pool.wait_completion()

        self.runtime = time.time() - self.runtime

        proxy_log[self.proxy_ip + "::" + self.target] = self.get_info()


class MultiScan:

    """

        Multiple Scanning using multiprocessing, calls the Scan
        class which scans creates multiple threads, from the given
        list of IPs each proccessor is assigned with a single IP to
        scan ports of.

        Arguments:

            target: list - List of IP Addresses
            ports: list - List of ports to scan
            threads: int - Number of threads to use
            timeout: int - Socket connection timeout in seconds
            proxy_ip: list - The proxy IPs to use
            proxy_port: list - Proxy port to use

        Methods:

            run_full_scan - Scanning all the ports
            run_proxy_scan - Scanning through a proxy

    """

    def __init__(self, targets, ports=range(65536), threads=100, timeout=3, proxy_ip: list=["127.0.0.1"], proxy_port: list=[80]):

        self.targets = targets
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port

        self.worker_pool = []
        self.worker_count = cpu_count()
        self.job_len = len(targets)

        self.scanners = [Scan(self.targets[i], self.ports, self.threads,
                              self.timeout, self.proxy_ip, self.proxy_port)
                         for i in range(self.job_len)]
        
        self.scan_secure = [Scan(self.targets[i], self.ports, self.threads,
                                 self.timeout, self.proxy_ip[0],
                                 self.proxy_port[0])
                            for i in range(self.job_len)]
        
        self.scan_unsecure = [Scan(self.targets[i], self.ports, self.threads,
                                   self.timeout, self.proxy_ip[1],
                                   self.proxy_port[1])
                              for i in range(self.job_len)]

        self.manager = multiprocessing.Manager()
        self.log = self.manager.dict()
        self.proxy_log = self.manager.dict()

        self.total_runtime = 0

    def run_full_scan(self):

        """

            Run a complete scan of off a list of IPs for the entire port
            range.

        """

        self.total_runtime = time.time()

        i = 0
        while (i < self.job_len):
            self.worker_pool = []
            for _ in range(self.worker_count):
                if i >= self.job_len:
                    break

                p = Process(target=self.scanners[i].run, args=(self.log,))
                p.start()
                self.worker_pool.append(p)

                i += 1

            for p in self.worker_pool:
                p.join()

        self.total_runtime = time.time() - self.total_runtime

    def run_proxy_scan(self, safe_flag: bool=True):

        self.total_runtime = time.time()

        i = 0
        while (i < self.job_len):
            self.worker_pool = []
            for _ in range(self.worker_count):
                if i >= self.job_len:
                    break

                if safe_flag:
                    p = Process(target=self.scan_secure[i].run,
                                args=(self.proxy_log, True))
                else:
                    p = Process(target=self.scan_unsecure[i].run,
                                args=(self.proxy_log, True))

                p.start()
                self.worker_pool.append(p)

                i += 1

            for p in self.worker_pool:
                p.join()

        self.total_runtime = time.time() - self.total_runtime


if __name__ == "__main__":
    mulScan = MultiScan(["192.99.7.28", "192.168.1.99"], range(100), 100, 1,
                        ["104.225.218.192", "117.212.95.161"],
                        [3128, 8080])
    
    mulScan.run_proxy_scan(True)
    mulScan.run_proxy_scan(False)

    print(mulScan.proxy_log)
