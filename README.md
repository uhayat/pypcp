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
You can also get results for each command in JSON format. For above example JSON result will look like following:

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


PCP_CLI
-------
Based on pyPCP library, a utility is also available with name pcp_cli.py
pcp_cli provide functionaliy of all pcp_* utilities provided with Pgpool-II in a single app. Multiple commands are available with there respective sub-commands/groups. 

Following example show 'pcp_cli node count':

    uhayat$ python pcp_cli.py node count -U postgres -H pgpool_host -v
    Password: 
    Node Count
    ____________
    2

pcp_cli available command & sub-commands:

- pool status
- pool stop
- pool reload-config
- pool check-health-stats
- node count
- node info
- node attach
- node detach
- node promote
- node recovery
- process count
- process info
- watchdog info