import unittest
import port_scanner


class TestPortScanner(unittest.TestCase):

    def setUp(self):

        self.scan_1 = port_scanner.Scan(target="192.99.7.28",
                                        ports=[80],
                                        threads=100,
                                        timeout=3)
        self.scan_2 = port_scanner.Scan(target="192.99.7.28",
                                        ports=[1],
                                        threads=100,
                                        timeout=3)
        
        self.mulScan_1 = port_scanner.MultiScan(targets=["192.99.7.28"],
                                                ports=[80],
                                                threads=100,
                                                timeout=3)
        self.mulScan_2 = port_scanner.MultiScan(targets=["192.99.7.28"],
                                                ports=[1],
                                                threads=100,
                                                timeout=3)

    def test_pscan(self):

        self.scan_1.pscan(self.scan_1.ports[0])
        self.scan_2.pscan(self.scan_2.ports[0])
        
        self.assertEqual(self.scan_1.opened, 1)
        self.assertEqual(self.scan_1.open_ports, [80])

        self.assertEqual(self.scan_2.closed, 1)
        self.assertEqual(self.scan_2.closed_ports, [1])
    
    def test_run(self):

        log_1, log_2 = {}, {}
        self.scan_1.run(log_1)
        self.scan_2.run(log_2)

        self.assertEqual(self.scan_1.closed, 0)
        self.assertEqual(self.scan_1.closed_ports, [])
        self.assertEqual(self.scan_1.opened, 1)
        self.assertEqual(self.scan_1.open_ports, [80])

        self.assertGreater(self.scan_1.runtime, 0)

        self.assertEqual(self.scan_2.closed, 1)
        self.assertEqual(self.scan_2.closed_ports, [1])
        self.assertEqual(self.scan_2.opened, 0)
        self.assertEqual(self.scan_2.open_ports, [])

        self.assertGreater(self.scan_2.runtime, 0)
    
    def test_run_full_scan(self):

        self.mulScan_1.run_full_scan()
        self.mulScan_2.run_full_scan()

        self.assertEqual(self.mulScan_1.log[self.mulScan_1.targets[0]]["Number of Closed Ports"], 0)
        self.assertEqual(self.mulScan_1.log[self.mulScan_1.targets[0]]["Closed Ports"], [])
        self.assertEqual(self.mulScan_1.log[self.mulScan_1.targets[0]]["Number of Open Ports"], 1)
        self.assertEqual(self.mulScan_1.log[self.mulScan_1.targets[0]]["Opened Ports"], [80])
        self.assertEqual(self.mulScan_1.job_len, 1)
        self.assertGreater(self.mulScan_1.log[self.mulScan_1.targets[0]]["Runtime"], 0)

        self.assertEqual(self.mulScan_2.log[self.mulScan_2.targets[0]]["Number of Closed Ports"], 1)
        self.assertEqual(self.mulScan_2.log[self.mulScan_2.targets[0]]["Closed Ports"], [1])
        self.assertEqual(self.mulScan_2.log[self.mulScan_2.targets[0]]["Number of Open Ports"], 0)
        self.assertEqual(self.mulScan_2.log[self.mulScan_2.targets[0]]["Opened Ports"], [])
        self.assertEqual(self.mulScan_2.job_len, 1)
        self.assertGreater(self.mulScan_2.log[self.mulScan_2.targets[0]]["Runtime"], 0)



if __name__ == "__main__":
    unittest.main()