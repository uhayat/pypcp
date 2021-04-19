pyPCP
=====

Python library for Pgpool-II Communication Protocol(PCP).

pyPCP provides a interface for administrators to perform management operation, such as getting `Pgpool-II`_  status or terminating `Pgpool-II`_ processes remotely.

`Pgpool-II`_ installation is not required on local machine

.. _Pgpool-II: https://github.com/pgpool/pgpool2

Installing
----------
Install and Update using pip.

.. code-block:: text

    $ pip install pypcp

Example Usage
-------------
.. code-block:: python

    from pypcp import PCP, ResultStateType

    pcp = PCP()
    pcp.pcp_connect('remote_ip', 9898, 'postgres', 'secret')
    result = pcp.pcp_node_count()
    if result and pcp.PCPResultStatus(result) == ResultStateType.COMMAND_OK:
         print('Node Count  : ', result.pcp_get_data(0))
    pcp.pcp_disconnect()

.. code-block:: text

    $ Node Count  : 2

JSON Support
------------
You can also get results for each command in JSON format.

.. code-block:: python

    print(result.pcp_get_json_data(0))

.. code-block:: text

    $ {'command_status': 'success', 'node_count': 2}

Supported Commands
------------------
Following commands are supported by pyPCP. Details about each command can be found at `PCP Commands`_

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

.. _PCP Commands: https://www.pgpool.net/docs/latest/en/html/pcp-commands.html

PCP_CLI
-------
Based on pyPCP library, a cli utility is also available with name pcp_cli
pcp_cli provide functionality of all pcp_* utilities provided with Pgpool-II in a single app. Multiple commands are available with there respective sub-commands/groups. 

Following example show 'pcp_cli node count':

.. code-block:: text

    $ pcp_cli node count -U postgres -H pgpool_host -v
    Password: 
    Node Count
    ____________
    2

List of pcp_cli commands & sub-commands:

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