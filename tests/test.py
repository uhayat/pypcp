#! /usr/local/opt/python/bin/python3.7
import unittest
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__),'..','src'))
from pypcp import PCP
from pypcp import ConnStateType, ResultStateType
from pypcp import SERVER_ROLE, BACKEND_STATUS

class PCPTest(unittest.TestCase):

    def setUp(self):
        self.host = '172.16.169.150' #'localhost'
        self.port = 9898
        self.user = 'postgres'
        self._pass = 'postgres'
        self._debug = False
        self._show_json = False
        self._pcp = PCP()
        self.makeConnection()
    
    def tearDown(self):
        self._pcp.pcp_disconnect()
    
    def makeConnection(self):
        self._pcp.pcp_connect(self.host, self.port, self.user, self._pass)
        self._pcp.set_debug_stream(self._debug)

        if self._pcp.PCPConnectionStatus() != ConnStateType.OK:
            if self._pcp.pcp_get_last_error():
                sys.stderr.write("%s\n"% self._pcp.pcp_get_last_error())
            else:
                sys.stderr.write("%s\n"% "Unknown Error")
            exit(1)

    def test_node_count(self):
        pcpResInfo = self._pcp.pcp_node_count()
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())

    def test_node_info(self):
        pcpResInfo = self._pcp.pcp_node_info(0)
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        backend_info = pcpResInfo.pcp_get_data(0)
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())

    def test_proc_count(self):
        pcpResInfo = self._pcp.pcp_process_count()
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        process_list = pcpResInfo.results[0] 
        process_count = len(process_list)
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())

    def test_proc_info(self):
        pcpResInfo = self._pcp.pcp_process_count()
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        process_list = pcpResInfo.results[0] 
        process_count = len(process_list)
        pcpResInfo = self._pcp.pcp_process_info(process_list[0])
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        array_size = len(pcpResInfo.results)
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())
        for i in range(0, array_size):
            process_info =  pcpResInfo.results[i]

    def test_pool_status(self):
        pcpResInfo = self._pcp.pcp_pool_status()
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())
        for i, poolReportConfig in enumerate(pcpResInfo.results):
            pass

    def test_watchdog_info(self):
        pcpResInfo = self._pcp.pcp_watchdog_info(0)
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())

    def test_attach_node(self):
        pcpResInfo = self._pcp.pcp_attach_node(0)
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')

    def test_detach_node(self):
        pcpResInfo = self._pcp.pcp_detach_node(0)
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())
        
    def test_promote_node(self):
        pcpResInfo = self._pcp.pcp_promote_node(0)
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())
        
    def test_recovery_node(self):
        pcpResInfo = self._pcp.pcp_recovery_node(0)
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) != ResultStateType.COMMAND_OK, 'ResultStateType is OK' + self._pcp.pcp_get_last_error())
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())
        
    def test_health_check_stats(self):
        pcpResInfo = self._pcp.pcp_health_check_stats(0)
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK')
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())
        
    def test_pcp_reload_config(self):
        pcpResInfo = self._pcp.pcp_reload_config('l')
        self.assertTrue(pcpResInfo != None, 'pcpResInfo is None')
        self.assertTrue(self._pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK, 'ResultStateType is not OK' )
        if self._show_json:
            print(pcpResInfo.pcp_get_json_data())
        
if __name__ == "__main__":
    unittest.main()