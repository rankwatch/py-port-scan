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
            func, args, kwargs = self.tasks.get()
            try:
                func(*args, **kwargs)
            except Exception as e:
                print(e)
            finally:
                self.tasks.task_done()


class ThreadPool:
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kwargs):
        self.tasks.put((func, args, kwargs))

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
                 timeout: int=3, proxy_ip: list=["127.0.0.1", "127.0.0.1"],
                 proxy_port: list=[80, 80]):

        self._target_ = target
        self._no_of_threads_ = threads
        self._ports_ = ports
        self._timeout_ = timeout
        self._proxy_ip_ = proxy_ip
        self._proxy_port_ = proxy_port

        self._config_ = configparser.ConfigParser()
        self._config_.read("../CONFIG.ini")

        self._socks_type_ = int(self._config_["SOCKS"]["version"])

        self._closed_ = 0
        self._opened_ = 0
        self._open_ports_ = []
        self._closed_ports_ = []

        self._runtime_ = 0

    def set_socks_type_(self, socks_type):
        self._socks_type_ = socks_type

    def get_socks_type(self):
        return self._socks_type_

    def set_target(self, target):
        self._target_ = target

    def get_target(self):
        return self._target_

    def set_no_of_threads(self, no_of_threads):
        self._no_of_threads_ = no_of_threads

    def get_no_of_threads(self):
        return self._no_of_threads_

    def set_ports(self, ports):
        self._ports_ = ports

    def get_ports(self):
        return self._ports_

    def set_timeout(self, timeout):
        self._timeout_ = timeout

    def get_timeout(self):
        return self._timeout_

    def set_proxy_ip(self, proxy_ip):
        self._proxy_ip_ = proxy_ip

    def get_proxy_ip(self):
        return self._proxy_ip_

    def set_proxy_port(self, proxy_port):
        self._proxy_port_ = proxy_port

    def get_proxy_port(self):
        return self._proxy_port_

    def get_open_ports(self):
        return self._open_ports_

    def get_opened(self):
        return self._opened_

    def get_closed_ports(self):
        return self._closed_ports_

    def get_closed(self):
        return self._closed_

    def pscan(self, port: int) -> None:

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
            s.settimeout(self._timeout_)
            con = s.connect((self._target_, port))

            self._opened_ += 1
            self._open_ports_.append(port)

        except Exception as e:
            self._closed_ += 1
            self._closed_ports_.append(port)

    def proxy_scan(self, port: int) -> None:

        try:

            s = socks.socksocket()
            s.settimeout(self._timeout_)

            if self._socks_type_ == 5:
                s.set_proxy(socks.PROXY_TYPE_SOCKS5,
                            self._proxy_ip_, self._proxy_port_,
                            True)
            elif self._socks_type_ == 4:
                s.set_proxy(socks.PROXY_TYPE_SOCKS4,
                            self._proxy_ip_, self._proxy_port_,
                            True)

            s.connect((self._target_, port))

            self._opened_ += 1
            self._open_ports_.append(port)

        except:

            self._closed_ += 1
            self._closed_ports_.append(port)

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
        return {"Number of Open Ports": self._opened_,
                "Number of Closed Ports": self._closed_,
                "Opened Ports": self._open_ports_,
                "Closed Ports": self._closed_ports_,
                "Runtime": self._runtime_}

    def run(self, log: dict) -> None:

        """

            Executes the scan after creating a threadpool and
            also stores and calculates the runtime.

            Arguments:

                log: dict - The shared dictionary among all the threads

        """

        self._runtime_ = time.time()
        pool = ThreadPool(self._no_of_threads_)

        pool.map(self.pscan, self._ports_)
        pool.wait_completion()

        self._runtime_ = time.time() - self._runtime_

        log[self._target_] = self.get_info()

    def run_proxy(self, proxy_log: dict, flag: bool) -> None:

        self._runtime_ = time.time()
        pool = ThreadPool(self._no_of_threads_)

        pool.map(self.proxy_scan, self._ports_)
        pool.wait_completion()

        self._runtime_ = time.time() - self._runtime_

        proxy_log[self._proxy_ip_ + "::" + self._target_] = self.get_info()


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

    def __init__(self, targets, ports=range(65536), threads=100, timeout=3,
                 proxy_ip: list=["127.0.0.1", "127.0.0.1"],
                 proxy_port: list=[80, 80]):

        self._targets_ = targets
        self._ports_ = ports
        self._threads_ = threads
        self._timeout_ = timeout
        self._proxy_ip_ = proxy_ip
        self._proxy_port_ = proxy_port

        self._worker_pool_ = []
        self._worker_count_ = cpu_count()
        self._job_len_ = len(targets)

        self._scanners_ = [Scan(self._targets_[i], self._ports_,
                                self._threads_,
                                self._timeout_, self._proxy_ip_,
                                self._proxy_port_)
                           for i in range(self._job_len_)]

        self._scan_secure_ = [Scan(self._targets_[i], self._ports_,
                                   self._threads_,
                                   self._timeout_, self._proxy_ip_[0],
                                   self._proxy_port_[0])
                              for i in range(self._job_len_)]

        self._scan_unsecure_ = [Scan(self._targets_[i], self._ports_,
                                     self._threads_,
                                     self._timeout_, self._proxy_ip_[1],
                                     self._proxy_port_[1])
                                for i in range(self._job_len_)]

        self._manager_ = multiprocessing.Manager()
        self._log_ = self._manager_.dict()
        self._proxy_log_ = self._manager_.dict()

        self._total_runtime_ = 0

    def set_targets(self, targets):
        self._targets_ = targets

    def get_targets(self):
        return self._targets_

    def set_ports(self, ports):
        self._ports_ = ports

    def get_ports(self):
        return self._ports_

    def set_threads(self, threads):
        self._threads_ = threads

    def get_threads(self):
        return self._threads_

    def set_timeout(self, timeout):
        self._timeout_ = timeout

    def get_timeout(self):
        return self._timeout_

    def set_proxy_ip(self, proxy_ip):
        self._proxy_ip_ = proxy_ip

    def get_proxy_ip(self):
        return self._proxy_ip_

    def set_proxy_ports(self, proxy_ports):
        self._proxy_ports_ = proxy_ports

    def get_proxy_ports(self):
        return self._proxy_ports_

    def get_worker_pool(self):
        return self._worker_pool_

    def get_worker_count(self):
        return self._worker_count_

    def get_job_len(self):
        return self._job_len_  # TODO: in case of reusing the same object this value will not change.

    def get_total_runtime(self):
        return self._total_runtime_

    def get_log(self):  # TODO: The getters are not in use in your own code.
        return self._log_

    def get_proxy_log(self):
        return self._proxy_log_

    def run_full_scan(self) -> dict:

        """

            Run a complete scan of off a list of IPs for the entire port
            range.

        """

        self._total_runtime_ = time.time()

        i = 0
        while (i < self._job_len_):  # TODO: You have a getter for this, use it.
            self._worker_pool_ = []
            for _ in range(self._worker_count_):
                if i >= self._job_len_:
                    break

                p = Process(target=self._scanners_[i].run, args=(self._log_,))
                p.start()
                self._worker_pool_.append(p)

                i += 1

            for p in self._worker_pool_:
                p.join()

        self._total_runtime_ = time.time() - self._total_runtime_
        return self._log_

    def run_proxy_scan(self, safe_flag: bool) -> dict:

        self._total_runtime_ = time.time()

        i = 0
        while i < self._job_len_:
            self._worker_pool_ = []
            for _ in range(self._worker_count_):
                if i >= self._job_len_:
                    break

                if safe_flag:
                    p = Process(target=self._scan_secure_[i].run_proxy,
                                args=(self._proxy_log_, True))
                else:
                    p = Process(target=self._scan_unsecure_[i].run_proxy,
                                args=(self._proxy_log_, True))

                p.start()
                self._worker_pool_.append(p)

                i += 1

            for p in self._worker_pool_:
                p.join()

        self._total_runtime_ = time.time() - self._total_runtime_
        return self._proxy_log_
