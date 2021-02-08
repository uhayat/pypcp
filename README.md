pyPCP
=========

Python library for Pgpool-II Communication Protocol(PCP).

pyPCP provides a interface for administrators to perform management operation, such as getting [Pgpool-II](https://github.com/pgpool/pgpool2) status or terminating [Pgpool-II](https://github.com/pgpool/pgpool2) processes remotely.

Pgpool installation is not required on local machine

Example
-------
    $ pcp = PCP()
    $ pcp.pcp_connect('remote_ip', '9898', 'postgres', 'secret')
    $ result = pcp.pcp_node_count()
    $ if result != None and pcp.PCPResultStatus(pcpResInfo) == ResultStateType.COMMAND_OK:
    $      print('Node Count : ', result.pcp_get_data(0))
    $ pcp.pcp_disconnect()