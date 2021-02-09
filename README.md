pyPCP
=========

Python library for Pgpool-II Communication Protocol(PCP).

pyPCP provides a interface for administrators to perform management operation, such as getting [Pgpool-II](https://github.com/pgpool/pgpool2) status or terminating [Pgpool-II](https://github.com/pgpool/pgpool2) processes remotely.

Pgpool installation is not required on local machine

Example Usage
-------------
    $ pcp = PCP()
    $ pcp.pcp_connect('remote_ip', '9898', 'postgres', 'secret')
    $ result = pcp.pcp_node_count()
    $ if result != None and pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK:
    $      print('Node Count  : ', result.pcp_get_data(0))
    $      print('JSON Result : ', result.pcp_get_json_data(0))
    $ pcp.pcp_disconnect()

JSON Support
------------
You can also results for each command. For above example JSON result will look like bellow:
    $ {'command_status': 'success', 'node_count': 2}

Supported Commands
------------------
Following commands are supported by pyPCP. Details about each command can be found at [PCP Commands](https://www.pgpool.net/docs/latest/en/html/pcp-commands.html)
	* pcp_proc_count
	* pcp_proc_info
	* pcp_attach_node
	* pcp_detach_node
	* pcp_stop_pgpool
	* pcp_pool_status
	* pcp_node_count
	* pcp_watchdog_info
	* pcp_node_info
	* pcp_stop_pgpool
	* pcp_promote_node
	* pcp_recovery_node
	* pcp_health_check_stats
	* pcp_reload_config
    * pcp_set_backend_parameter

