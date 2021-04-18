#!/usr/bin/env python

import sys
import time
import argparse
import datetime
from enum import Enum
from getpass import getpass
from .pcp import PCP
from .pcp import ConnStateType, ResultStateType
from .pcp import SERVER_ROLE, BACKEND_STATUS, MAX_NUM_BACKENDS

PACKAGE = 'PCP'
VERSION = '1.0'
RAND_MAX = 2147483647

class PCP_UTILITIES(Enum):
	PCP_ATTACH_NODE = 1
	PCP_DETACH_NODE = 2
	PCP_NODE_COUNT = 3
	PCP_NODE_INFO = 4
	PCP_POOL_STATUS = 5
	PCP_PROC_COUNT = 6
	PCP_PROC_INFO = 7
	PCP_PROMOTE_NODE = 8
	PCP_RECOVERY_NODE = 9
	PCP_STOP_PGPOOL = 10
	PCP_WATCHDOG_INFO = 11
	PCP_HEALTH_CHECK_STATS = 12 
	PCP_RELOAD_CONFIG = 13
	UNKNOWN = 14

AllAppTypes = {
	'node attach' : PCP_UTILITIES.PCP_ATTACH_NODE,
	'node detach' : PCP_UTILITIES.PCP_DETACH_NODE,
	'node count'  : PCP_UTILITIES.PCP_NODE_COUNT,
	'node info'   : PCP_UTILITIES.PCP_NODE_INFO,
	'pool status' : PCP_UTILITIES.PCP_POOL_STATUS,
	'process count'  : PCP_UTILITIES.PCP_PROC_COUNT,
	'process info'   : PCP_UTILITIES.PCP_PROC_INFO,
	'node promote'  : PCP_UTILITIES.PCP_PROMOTE_NODE,
	'node recovery' : PCP_UTILITIES.PCP_RECOVERY_NODE,
	'pool stop'   : PCP_UTILITIES.PCP_STOP_PGPOOL,
	'watchdog info' : PCP_UTILITIES.PCP_WATCHDOG_INFO,
	'pool check-health-stats' : PCP_UTILITIES.PCP_HEALTH_CHECK_STATS,
	'pool reload-config' : PCP_UTILITIES.PCP_RELOAD_CONFIG
	}

def check_pid(value):
	ivalue = int(value)
	if ivalue < 0:
		raise argparse.ArgumentTypeError(f'Invalid process-id "{value}", must be greater than 0')
	return value

def check_port(value):
	port = int(value)
	if port <= 1024 or port > 65535:
		raise argparse.ArgumentTypeError(f'Invalid port number "{port}", must be between 1024 and 65535')
	return value

def _createSubParser(app_name, parser):

	parser.add_argument('-d', '--debug', help='enable debug message (optional)', action='store_true')
	parser.add_argument('-v', '--verbose', help='verbose', action='store_true')

	if sys.platform == 'win32':
		parser.add_argument('-H', '--host', nargs=1, metavar=(('host')), help='pgpool-II host', required=True)
	else:
		parser.add_argument('-H', '--host', nargs=1, metavar=(('host')), help='pgpool-II host', default='')

	parser.add_argument('-p', '--port', nargs=1, metavar=(('port')), help='PCP port number', default=9898, 
						type=check_port)
	if app_name == 'pcp_proc_info':
		parser.add_argument('-P', '--process-id', nargs=1, metavar=('process_id'), 
		help='PID of the child process to get information for (optional)', 
		default=0, type=check_pid)
	parser.add_argument('-U', '--username', nargs=1, metavar=(('username')), help='username for PCP authentication')

	group = parser.add_mutually_exclusive_group()
	group.add_argument('-w', '--no-password', help='never prompt for password', action='store_true')
	group.add_argument('-W', '--password', help='force password prompt (should happen automatically)', 
						action='store_true', default=True)

	if app_name == 'pcp_stop_pgpool':
		parser.add_argument('-m', '--mode', nargs=1, metavar=(('mode')), 
						help='mode can be "s|smart", "f|fast", or "i|immediate" (The default is "smart")',
						choices=['s', 'smart', 'f', 'fast', 'i', 'immediate'], default='smart')

	if app_name in ['pcp_stop_pgpool', 'pcp_reload_config']:
		parser.add_argument('-s', '--scope', nargs=1, metavar=(('scope')), 
						help='scope can be "c|cluster", "l|local" (The default is "local")',
						choices=['c', 'cluster', 'l', 'local'], default='local')

	if app_name in ['pcp_detach_node', 'pcp_promote_node']:
		parser.add_argument('-g', '--gracefully', help='promote gracefully(optional)', action='store_true')

	if app_name == 'pcp_proc_info':
		parser.add_argument('-a', '--all', help='display all child processes and their available connection slots', 
		action='store_true')

	if app_name == 'pcp_watchdog_info':
		parser.add_argument('-n', '--watchdog-id', nargs=1, metavar=(('watchdog_id')), 
							help='ID of a other pgpool to get information for\nID 0 for the local watchdog\nIf omitted then get information of all watchdog nodes',
		 					type=int, required=True)
	elif app_name in ['pcp_attach_node', 'pcp_detach_node', 'pcp_node_info', 'pcp_promote_node', 'pcp_recovery_node', 'pcp_health_check_stats']:
		parser.add_argument('-n', '--node-id', nargs=1, metavar=(('node_id')), help='ID of a backend node',
							type=int, required=True)

def _createArgParser():
	parser = argparse.ArgumentParser(description='PCP Commands help.')
	parser.add_argument('-V', '--version', help='version', action='store_true')
	subparsers = parser.add_subparsers(title='PCP Commands', dest='command')
	parser_pool = subparsers.add_parser('pool', help='Pool management')
	pool_subparsers = parser_pool.add_subparsers(dest='pool_command')
	parser_pool_status = pool_subparsers.add_parser('status', help='display pgpool configuration and status')
	parser_pool_stop   = pool_subparsers.add_parser('stop', help='terminate pgpool-II')
	parser_pool_reload = pool_subparsers.add_parser('reload-config', help='reload pgpool configuration file')
	parser_pool_health = pool_subparsers.add_parser('check-health-stats', help='display a pgpool-II health check stats data')

	parser_node = subparsers.add_parser('node', help='Node management')
	node_subparsers    = parser_node.add_subparsers(title='PCP Node Commands', dest='node_command')
	parser_node_count  = node_subparsers.add_parser('count', help='display the total number of nodes under pgpool-II\'s control')
	parser_node_info   = node_subparsers.add_parser('info', help='display a pgpool-II node\'s information')
	parser_node_attach = node_subparsers.add_parser('attach', help='attach a node to pgpool-II')
	parser_node_detach = node_subparsers.add_parser('detach', help='detach a node from pgpool-II')
	parser_node_promote  = node_subparsers.add_parser('promote', help='promote a node as new primary from pgpool-II')
	parser_node_recovery = node_subparsers.add_parser('recovery', help='recover a node')

	parser_proc = subparsers.add_parser('process', help='Process management')
	proc_subparsers = parser_proc.add_subparsers(title='PCP Process Commands', dest='proc_command')
	parser_proc_count = proc_subparsers.add_parser('count', help='display the list of pgpool-II child process PIDs')
	parser_proc_info  = proc_subparsers.add_parser('info', help='display a pgpool-II child process\' information')

	parser_watchdog = subparsers.add_parser('watchdog', help='Watchdog management')
	watchdog_subparsers  = parser_watchdog.add_subparsers(title='PCP Watchdog Commands', dest='watchdog_command')
	parser_watchdog_info = watchdog_subparsers.add_parser('info', help='display a pgpool-II watchdog\'s information')

	_createSubParser('pool_status', parser_pool_status)
	_createSubParser('pcp_stop_pgpool', parser_pool_stop)
	_createSubParser('pcp_reload_config', parser_pool_reload)
	_createSubParser('pcp_health_check_stats', parser_pool_health)

	_createSubParser('pcp_node_count', parser_node_count)
	_createSubParser('pcp_node_info', parser_node_info)
	_createSubParser('pcp_attach_node', parser_node_attach)
	_createSubParser('pcp_detach_node', parser_node_detach)
	_createSubParser('pcp_promote_node', parser_node_promote)
	_createSubParser('pcp_recovery_node', parser_node_recovery)

	_createSubParser('pcp_proc_count', parser_proc_count)
	_createSubParser('pcp_proc_info', parser_proc_info)
	_createSubParser('pcp_watchdog_info', parser_watchdog_info)

	return parser

def check_command(_parser, args):
	complete_command = True
	command_path =list()
	if not args.command:
		complete_command = False
	elif args.command == 'pool':
		command_path.append('pool')
		if not args.pool_command:
			complete_command = False
		else:
			command_path.append(args.pool_command)
	elif args.command == 'node':
		command_path.append('node')
		if not args.node_command:
			complete_command = False
		else:
			command_path.append(args.node_command)
	elif args.command == 'process':
		command_path.append('process')
		if not args.proc_command:
			complete_command = False
		else:
			command_path.append(args.proc_command)
	elif args.command == 'watchdog':
		command_path.append('watchdog')
		if not args.watchdog_command:
			complete_command = False
		else:
			command_path.append(args.watchdog_command)

	if not complete_command:
		_parser.parse_args(command_path + ['-h'])
		exit(1)

	return ' '.join(command_path)

def frontend_client(argc,  argv):
	host = None
	port = 9898
	user = None
	_pass = None
	nodeID = -1
	processID = 0
	shutdown_mode = 's'
	command_scope = 'l'
	pcpResInfo = None

	_pcp = PCP()

	_parser = _createArgParser()
	args = _parser.parse_args()

	if args.version:
		sys.stderr.write(f'pcp_cli ({PACKAGE}) {VERSION}\n')
		exit(0)
		
	progname = check_command(_parser, args)
		
	if not progname in AllAppTypes:
		sys.stderr.write(f'{progname} is a invalid PCP command\n')
		exit(1)

	current_app_type = AllAppTypes[progname]

	if 'process_id' in args:			# PID
		if args.process_id:
			processID = int(args.process_id[0])

	if 'node_id' in args:
		nodeID = int(args.node_id[0])
		if current_app_type == PCP_UTILITIES.PCP_WATCHDOG_INFO:
			if (nodeID < 0):
				sys.stderr.write(f'{progname}: Invalid watchdog-id "{args.node_id}", must be a positive number or zero for a local watchdog node\n')
				exit(0)
		else:
			if nodeID < 0 or nodeID > MAX_NUM_BACKENDS:
				sys.stderr.write(f'{progname}: Invalid node-id "{args.node_id}", must be between 0 and {MAX_NUM_BACKENDS}\n')
				exit(0)

	if 'mode' in args:
		if args.mode:
			shutdown_mode = args.mode[0][0]

	if 'scope' in args:
		if args.scope:
			command_scope = args.scope[0][0]

	if args.port:
		port = args.port

	if args.host:
		host = args.host[0]

	if args.username:
		user = args.username[0]

	# Get a new password if appropriate
	if args.password and not args.no_password:
		_pass = getpass('Password: ')

	_debug = None
	if args.debug:
		_debug = sys.stdout

	_pcp.pcp_connect(host, port, user, _pass)
	_pcp.set_debug_stream(_debug)

	if _pcp.PCPConnectionStatus() != ConnStateType.OK:
		if _pcp.pcp_get_last_error():
			sys.stderr.write(f'{_pcp.pcp_get_last_error()}\n')
		else:
			sys.stderr.write('Unknown Error\n')
		exit(1)

	#
	# Okay the connection is successful not call the actual PCP function
	#
	if (current_app_type == PCP_UTILITIES.PCP_ATTACH_NODE):
		pcpResInfo = _pcp.pcp_attach_node(nodeID)

	elif (current_app_type == PCP_UTILITIES.PCP_DETACH_NODE):
		if args.gracefully:
			pcpResInfo = _pcp.pcp_detach_node_gracefully(nodeID)
		else:
			pcpResInfo = _pcp.pcp_detach_node(nodeID)

	elif (current_app_type == PCP_UTILITIES.PCP_NODE_COUNT):
		pcpResInfo = _pcp.pcp_node_count()

	elif (current_app_type == PCP_UTILITIES.PCP_NODE_INFO):
		pcpResInfo = _pcp.pcp_node_info(nodeID)

	elif (current_app_type == PCP_UTILITIES.PCP_HEALTH_CHECK_STATS):
		pcpResInfo = _pcp.pcp_health_check_stats(nodeID)

	elif (current_app_type == PCP_UTILITIES.PCP_POOL_STATUS):
		pcpResInfo = _pcp.pcp_pool_status()

	elif (current_app_type == PCP_UTILITIES.PCP_PROC_COUNT):
		pcpResInfo = _pcp.pcp_process_count()

	elif (current_app_type == PCP_UTILITIES.PCP_PROC_INFO):
		pcpResInfo = _pcp.pcp_process_info(processID)

	elif (current_app_type == PCP_UTILITIES.PCP_PROMOTE_NODE):
		if args.gracefully:
			pcpResInfo = _pcp.pcp_promote_node_gracefully(nodeID)
		else:
			pcpResInfo = _pcp.pcp_promote_node(nodeID)

	elif (current_app_type == PCP_UTILITIES.PCP_RECOVERY_NODE):
		pcpResInfo = _pcp.pcp_recovery_node(nodeID)

	elif (current_app_type == PCP_UTILITIES.PCP_STOP_PGPOOL):
		pcpResInfo = _pcp.pcp_terminate_pgpool(shutdown_mode, command_scope)

	elif (current_app_type == PCP_UTILITIES.PCP_WATCHDOG_INFO):
		pcpResInfo = _pcp.pcp_watchdog_info(nodeID)

	elif (current_app_type == PCP_UTILITIES.PCP_RELOAD_CONFIG):
		pcpResInfo = _pcp.pcp_reload_config(command_scope)

	else:
		# should never happen
		sys.stderr.write(f'{progname}: Invalid pcp process\n')
		_pcp.pcp_disconnect()
		return

	if (pcpResInfo == None or pcpResInfo.resultStatus != ResultStateType.COMMAND_OK):
		if _pcp.pcp_get_last_error():
			sys.stderr.write(f'{_pcp.pcp_get_last_error()}\n')
		else:
			sys.stderr.write('Unknown Error\n')
		_pcp.pcp_disconnect()
		return

	if pcpResInfo.pcp_result_is_empty():
		sys.stdout.write(f'{progname} -- Command Successful\n')
	else:
		if (current_app_type == PCP_UTILITIES.PCP_NODE_COUNT):
			output_nodecount_result(_pcp, pcpResInfo, args.verbose)
		elif (current_app_type == PCP_UTILITIES.PCP_NODE_INFO):
			output_nodeinfo_result(_pcp, pcpResInfo, args.verbose)
		elif (current_app_type == PCP_UTILITIES.PCP_POOL_STATUS):
			output_poolstatus_result(pcpResInfo, args.verbose)
		elif (current_app_type == PCP_UTILITIES.PCP_PROC_COUNT):
			output_proccount_result(pcpResInfo, args.verbose)
		elif (current_app_type == PCP_UTILITIES.PCP_PROC_INFO):
			output_procinfo_result(pcpResInfo, args.all, args.verbose)
		elif (current_app_type == PCP_UTILITIES.PCP_WATCHDOG_INFO):
			output_watchdog_info_result(_pcp, pcpResInfo, args.verbose)
		elif (current_app_type == PCP_UTILITIES.PCP_HEALTH_CHECK_STATS):
			output_health_check_stats_result(_pcp, pcpResInfo, args.verbose)

def output_nodecount_result(_pcp, pcpResInfo, verbose):
	if (verbose):
		print('Node Count')
		print('____________')
		print(f' {pcpResInfo.pcp_get_data(0)}')
	else:
		print(f'{pcpResInfo.pcp_get_data(0)}')

def output_nodeinfo_result(_pcp, pcpResInfo, verbose):
	backend_info = pcpResInfo.pcp_get_data(0)
	last_status_change = ''

	last_status_change = datetime.datetime.fromtimestamp(backend_info.status_changed_time).strftime('%F %T')

	if verbose:
		titles = ('Hostname', 'Port', 'Status', 'Weight', 'Status Name', 'Role', 'Replication Delay', 'Replication State', 'Replication Sync State', 'Last Status Change')
		types = ('s', 'd', 'd', 'f', 's', 's', 'lu', 's', 's', 's')

		format_string = format_titles(titles, types)
		print(format_string % (
			   backend_info.backend_hostname,
			   backend_info.backend_port,
			   backend_info.backend_status.value,
			   backend_info.backend_weight / RAND_MAX,
			   backend_status_to_string(backend_info),
			   backend_info.role,
			   backend_info.standby_delay,
			   backend_info.replication_state,
			   backend_info.replication_sync_state,
			   last_status_change))
	else:
		print('{} {} {} {} {} {} {} {} {} {}\n'.format(
			   backend_info.backend_hostname,
			   backend_info.backend_port,
			   backend_info.backend_status.value,
			   backend_info.backend_weight / RAND_MAX,
			   backend_status_to_string(backend_info),
			   backend_info.role,
			   backend_info.standby_delay,
			   backend_info.replication_state,
			   backend_info.replication_sync_state,
			   last_status_change))

def output_health_check_stats_result(_pcp, pcpResInfo, verbose):
	"""
	Format and output health check stats
	"""
	stats = pcpResInfo.pcp_get_data(0)

	if verbose:
		titles = ("Node Id", "Host Name", "Port", "Status", "Role", "Last Status Change",
								"Total Count", "Success Count", "Fail Count", "Skip Count", "Retry Count",
								"Average Retry Count", "Max Retry Count", "Max Health Check Duration",
								"Minimum Health Check Duration", "Average Health Check Duration",
								"Last Health Check", "Last Successful Health Check",
								"Last Skip Health Check", "Last Failed Health Check")
		types = ("s", "s", "s", "s", "s", "s", "s", "s", "s", "s",
							   "s", "s", "s", "s", "s", "s", "s", "s", "s", "s")
		format_string = format_titles(titles, types)
		print(format_string % (
			   stats['node_id'],
			   stats['hostname'],
			   stats['port'],
			   stats['status'],
			   stats['role'],
			   stats['last_status_change'],
			   stats['total_count'],
			   stats['success_count'],
			   stats['fail_count'],
			   stats['skip_count'],
			   stats['retry_count'],
			   stats['average_retry_count'],
			   stats['max_retry_count'],
			   stats['max_health_check_duration'],
			   stats['min_health_check_duration'],
			   stats['average_health_check_duration'],
			   stats['last_health_check'],
			   stats['last_successful_health_check'],
			   stats['last_skip_health_check'],
			   stats['last_failed_health_check']))
	else:
		print("%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n".format(
			   stats['node_id'],
			   stats['hostname'],
			   stats['port'],
			   stats['status'],
			   stats['role'],
			   stats['last_status_change'],
			   stats['total_count'],
			   stats['success_count'],
			   stats['fail_count'],
			   stats['skip_count'],
			   stats['retry_count'],
			   stats['average_retry_count'],
			   stats['max_retry_count'],
			   stats['max_health_check_duration'],
			   stats['min_health_check_duration'],
			   stats['average_health_check_duration'],
			   stats['last_health_check'],
			   stats['last_successful_health_check'],
			   stats['last_skip_health_check'],
			   stats['last_failed_health_check']))

def output_poolstatus_result(pcpResInfo, verbose):

	for i, status in enumerate(pcpResInfo.results):
		if verbose:
			if status:
				print(f'Name [{i:03}]:\t{status.name}')
				print(f'Value:      \t{status.value}')
				print(f'Description:\t{status.desc}\n')
			else:
				print(f'Name [{i:03}]:\tNULL')
				print(f'Value:      \tNULL')
				print(f'Description:\tNULL\n')
		else:
			if status == None:
				print(f'****Data at {i} slot is NULL')
				continue
			print(f'name : {status.name}\nvalue: {status.value}\ndesc : {status.desc}\n')

def output_proccount_result(pcpResInfo, verbose):
	process_list = pcpResInfo.results[0]

	if verbose:
		print('No \t | \t PID')
		print('_____________________')
		for i, pid in enumerate(process_list):
			print(f'{i} \t | \t {pid}')
		print(f'\nTotal Processes:{len(process_list)}')
	else:
		for pid in process_list:
			print(f'{pid} ', end='')
		print('')

def output_procinfo_result(pcpResInfo, _all, verbose):
	printed = False
	frmt = ''
	strcreatetime = ''
	strstarttime  = ''

	if verbose:
		frmt =  'Database     : {}\n' 
		frmt += 'Username     : {}\n'
		frmt += 'Start time   : {}\n'
		frmt += 'Creation time: {}\n'
		frmt += 'Major        : {}\n'
		frmt += 'Minor        : {}\n'
		frmt += 'Counter      : {}\n'
		frmt += 'Backend PID  : {}\n'
		frmt += 'Connected    : {}\n'
		frmt += 'PID          : {}\n'
		frmt += 'Backend ID   : {}\n'
	else:
		frmt = '{} {} {} {} {} {} {} {} {} {} {}\n'

	for process_info in pcpResInfo.results:
		if (process_info == None):
			break
		if ((not _all) and (process_info.connection_info.database == '')):
			continue

		printed = True
		strcreatetime = '' 
		strstarttime  = ''

		if (process_info.start_time):
			strstarttime = datetime.datetime.fromtimestamp(process_info.start_time).strftime('%Y-%m-%d %H:%M:%S')
		if (process_info.connection_info.create_time):
			strcreatetime = datetime.datetime.fromtimestamp(process_info.connection_info.create_time).strftime('%Y-%m-%d %H:%M:%S')

		print(frmt.format(
			   process_info.connection_info.database,
			   process_info.connection_info.user,
			   strstarttime,
			   strcreatetime,
			   process_info.connection_info.major,
			   process_info.connection_info.minor,
			   process_info.connection_info.counter,
			   process_info.connection_info.pid,
			   process_info.connection_info.connected,
			   process_info.pid,
			   process_info.connection_info.backend_id))
	if printed == False:
		print('No process information available\n')

def output_watchdog_info_result(_pcp, pcpResInfo, verbose):
	cluster = pcpResInfo.pcp_get_data(0)

	if verbose:
		quorumStatus = ''

		if (cluster.quorumStatus == 0):
			quorumStatus = 'QUORUM IS ON THE EDGE'
		elif (cluster.quorumStatus == 1):
			quorumStatus = 'QUORUM EXIST'
		elif (cluster.quorumStatus == -1):
			quorumStatus = 'QUORUM ABSENT'
		elif (cluster.quorumStatus == -2):
			quorumStatus = 'NO LEADER NODE'
		else:
			quorumStatus = 'UNKNOWN'

		print('Watchdog Cluster Information')
		print(f'Total Nodes          : {cluster.remoteNodeCount + 1}')
		print(f'Remote Nodes         : {cluster.remoteNodeCount}')
		print(f'Quorum state         : {quorumStatus}')
		print(f'Alive Remote Nodes   : {cluster.aliveNodeCount}')
		print(f'VIP up on local node : {"YES" if cluster.escalated else "NO"}')
		print(f'Leader Node Name     : {cluster.leaderNodeName}')
		print(f'Leader Host Name     : {cluster.leaderHostName}\n')

		print('Watchdog Node Information \n')
		for watchdog_info in cluster.nodeList:
			print(f'Node Name      : {watchdog_info.nodeName}')
			print(f'Host Name      : {watchdog_info.hostName}')
			print(f'Delegate IP    : {watchdog_info.delegate_ip}')
			print(f'Pgpool port    : {watchdog_info.pgpool_port}')
			print(f'Watchdog port  : {watchdog_info.wd_port}')
			print(f'Node priority  : {watchdog_info.wd_priority}')
			print(f'Status         : {watchdog_info.state}')
			print(f'Status Name    : {watchdog_info.stateName}\n')
	else:
		print('{} {} {} {}\n'.format(
			   cluster.remoteNodeCount + 1,
			   'YES' if cluster.escalated else 'NO',
			   cluster.leaderNodeName,
			   cluster.leaderHostName))

		for watchdog_info in cluster.nodeList:
			print('{} {} {} {} {} {}'.format(
				   watchdog_info.nodeName,
				   watchdog_info.hostName,
				   watchdog_info.pgpool_port,
				   watchdog_info.wd_port,
				   watchdog_info.state,
				   watchdog_info.stateName))

def backend_status_to_string(bi):
	"""
	Translate the BACKEND_STATUS enum value to string.\n
	"""

	if bi.backend_status == BACKEND_STATUS.CON_DOWN:
		if bi.quarantine:
			return 'quarantine'
	return str(bi.backend_status)

def format_titles(titles, types):
	"""
	Build format string for -v output mode.\n\n

	titles: title string array\n
	types:  print format type string array (example: 'd')\n
	ntitles: size of the arrary\n
	"""
	maxlen = 0

	for title in titles:
		l = len(title)
		if l > maxlen: maxlen = l

	formatbuf = ''
	for i, title in enumerate(titles):
		formatbuf += f'{title}{(maxlen-len(title))*" "} : %{types[i]}\n'
	return formatbuf

def main():
	try:
		frontend_client(len(sys.argv),  sys.argv)
	except KeyboardInterrupt:
		print('\nOperation aborted')

if __name__ == '__main__':
	main()
