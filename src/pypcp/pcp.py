
import os
import sys
import re
import json
import socket
import getpass
import stat
from pathlib import Path
from enum import Enum
from .utils.pcp_md5 import pool_md5_hash, pool_md5_encrypt
from .utils.pcp_stream import UNIX_DOMAIN_PATH, PCP_CONNECTION

MAX_USER_PASSWD_LEN   = 128
MAX_NUM_BACKENDS      = 128
PCPPASSFILE = '.pcppass'
if sys.platform == 'win32':
	PCPPASSFILE = 'pcppass.conf'
DefaultHost = 'localhost'
NULL = b'\x00'

class PCP:
	"""
	Pgpool Communication Protocol(PCP) class
	"""

	def __init__(self):
		"""
		Pgpool Communication Protocol(PCP) init method
		"""
		self.pcpConn    = PCP_CONNECTION()
		self.errMsg     = None
		self.connState  = ConnStateType.NOT_CONNECTED
		self.pcpResInfo = None
		self.Pfdebug = None
	
	def set_debug_stream(self, _stream):
		self.Pfdebug = _stream

	def pcp_connect(self, hostname, port, username, password):
		"""
		Create connection with Pgpool
		"""

		fd = 0
		if hostname == None or hostname == '' or hostname.startswith('/'):
			if sys.platform == 'win32':
				self.pcp_internal_error(f'ERROR: hostname not provided')
				self.connState = ConnStateType.BAD
				return

			try:
				fd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
			except Exception as e: 
				self.pcp_internal_error(f'ERROR: failed to create UNIX domain socket. socket error "{e}"')
				self.connState = ConnStateType.BAD
				return

			path = None
			if hostname == None or hostname == '':
				path = UNIX_DOMAIN_PATH
				hostname = path
			else:
				path = hostname

			unix_addr = os.path.join(path, f'.s.PGSQL.{port}')

			try:
				fd.connect(unix_addr)
			except Exception as e:
				fd.close()
				self.pcp_internal_error(f'ERROR: connection to socket "{unix_addr}" failed with error "{e}"')
				self.connState = ConnStateType.BAD
				return
		else:
			try:
				fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			except Exception as e:
				self.pcp_internal_error(f'ERROR: failed to create INET domain socket with error "{e}"')
				self.connState = ConnStateType.BAD
				return

			try:
				fd.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			except Exception as e:
				fd.close()
				self.pcp_internal_error(f'ERROR: set socket option failed with error "{e}"')
				self.connState = ConnStateType.BAD
				return
			
			try:
				socket.gethostbyname(hostname)
			except socket.gaierror as e:
				fd.close()
				self.pcp_internal_error(f'ERROR: could not retrieve hostname. gethostbyname failed with error "{e}"')
				self.connState = ConnStateType.BAD
				return

			try:
				fd.connect((hostname, port))
			except OSError as e:
				fd.close()
				self.pcp_internal_error(f'ERROR: connection to host "{hostname}" failed with error "{e}"')
				self.connState = ConnStateType.BAD
				return
			
		self.pcpConn.pcp_open(fd)
		if self.pcpConn == None:
			fd.close()
			self.pcp_internal_error('ERROR: failed to allocate memory')
			self.connState = ConnStateType.BAD
			return
		
		self.connState = ConnStateType.CONNECTED

		#
		# If username is not provided. Use the os user name and do not complain
		# if it (getting os user name) gets failed
		#
		if username == None:
			username = getpass.getuser()

		#
		# If password is not provided. lookup in pcppass file
		#
		if password == None or password == '':
			password = self._PasswordFromFile(hostname, str(port), username)
		
		if self._pcp_authorize(username, password) < 0:
			self.pcpConn.pcp_close()
			self.pcpConn = None
			self.connState = ConnStateType.AUTH_ERROR
		else:
			self.connState = ConnStateType.OK

	def _process_salt_info_response(self, salt, length):
		self._setResultData(self.pcpResInfo,  salt)
		self._setCommandSuccessful()

	def _pcp_authorize(self, username, password):
		"""
		authenticate with pgpool using username and password\n
		return 0 on success, -1 otherwise
		"""
		md5 = ''
		salt = None
		encrypt_buf = ''

		if password == None:
			password = ''

		if username == None:
			username = ''

		if self.PCPConnectionStatus() != ConnStateType.CONNECTED:
			self.pcp_internal_error('ERROR: PCP authorization failed. invalid connection state.')
			return -1
		
		if len(username) >= MAX_USER_PASSWD_LEN:
			self.pcp_internal_error('ERROR: PCP authorization failed. username too long.')
			return -1

		# request salt
		self._PCPWrite('M'.encode(), 1)
		wsize = self.int_to_bytes(4)
		self._PCPWrite(wsize, 4)
		if self.PCPFlush() < 0:
			return -1

		pcpRes = self._process_pcp_response('M')
		if pcpRes and pcpRes.resultStatus != ResultStateType.COMMAND_OK:
			return -1

		salt = pcpRes.pcp_get_data(0)
		if salt == None:
			return -1

		# encrypt password
		md5 = pool_md5_hash(password.encode())
		encrypt_buf = pool_md5_encrypt(md5.encode(), username.encode())
		encrypt_buf = pool_md5_encrypt(encrypt_buf.encode(), salt)

		self._PCPWrite('R'.encode(), 1)
		wsize = self.int_to_bytes(len(username) + 1 + len(encrypt_buf) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(username.encode() + NULL, len(username) + 1)
		self._PCPWrite(encrypt_buf.encode() + NULL, len(encrypt_buf) + 1)
		if self.PCPFlush() < 0:
			return -1

		pcpRes = self._process_pcp_response('R')
		if pcpRes and pcpRes.resultStatus != ResultStateType.COMMAND_OK:
			return -1
		self.pcp_free_result()
		return 0

	def _process_pcp_response(self, sentMsg):
		# create empty result
		if self.pcpResInfo == None:
			self.pcpResInfo = PCPResultInfo()
			self.pcpResInfo.results = list()
		
		while (True):
			toc = self._PCPRead(1).decode()
			if not toc:
				self.pcp_internal_error('ERROR: unable to read data from socket.')
				self._setResultStatus(ResultStateType.ERROR)
				return self.pcpResInfo
			rsize = self._PCPRead(4)
			if not rsize:
				self.pcp_internal_error('ERROR: unable to read data from socket.')
				self._setResultStatus(ResultStateType.ERROR)
				return self.pcpResInfo
			
			rsize = self.bytes_to_int(rsize)
			buf = ''

			buf = self._PCPRead(rsize - 4)
			if not buf:
				self.pcp_internal_error('ERROR: unable to read data from socket.')
				self._setResultStatus(ResultStateType.ERROR)
				return self.pcpResInfo

			if self.Pfdebug:
				self.Pfdebug.write(f'DEBUG: recv: tos="{toc}", length={rsize}\n')

			if toc == 'r':			# Authentication Response
					if sentMsg != 'R':
						self._setResultStatus(ResultStateType.BAD_RESPONSE)
					if buf.decode().strip('\0') == 'AuthenticationOK':
						self.connState = ConnStateType.OK
						self._setResultStatus(ResultStateType.COMMAND_OK)
					else:
						self.pcp_internal_error(f'ERROR: authentication failed. reason="{buf}"')
						self._setResultStatus(ResultStateType.BACKEND_ERROR)
			elif toc == 'm':
				if sentMsg != 'M':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_salt_info_response(buf, rsize)
			elif toc == 'E':
				self._setResultStatus(ResultStateType.BACKEND_ERROR)
				self._process_error_response(toc, buf)
			elif toc == 'N':
				self._process_error_response(toc, buf)
				del buf
				continue
			elif toc == 'i':
				if sentMsg != 'I':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_node_info_response(buf, rsize)
			elif toc == 'h':
				if sentMsg != 'H':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_health_check_stats_response(buf, rsize)
			elif toc == 'l':
				if sentMsg != 'L':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_pcp_node_count_response(buf, rsize)
			elif toc == 'c':
				if sentMsg != 'C' and sentMsg != 'O':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_command_complete_response(buf, rsize)
			elif toc == 'd':
				if sentMsg != 'D' and sentMsg != 'J':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_command_complete_response(buf, rsize)
			elif toc == 'a':
				if sentMsg != 'A':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_command_complete_response(buf, rsize)
			elif toc == 'z':
				if sentMsg != 'Z':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_command_complete_response(buf, rsize)
			elif toc == 'w':
				if sentMsg != 'W':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_watchdog_info_response(buf, rsize)
			elif toc == 'p':
				if sentMsg != 'P':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_process_info_response(buf, rsize)
			elif toc == 'n':
				if sentMsg != 'N':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_process_count_response(buf, rsize)
			elif toc == 'b':
				if sentMsg != 'B':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._process_pool_status_response(buf, rsize)
			elif toc == 't':
				if sentMsg != 'T':
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
				else:
					self._setResultStatus(ResultStateType.COMMAND_OK)
			else:
				self._setResultStatus(ResultStateType.BAD_RESPONSE)
				self.pcp_internal_error(f'ERROR: invalid PCP packet type ="{toc}"')
			
			if self.pcpResInfo and self.pcpResInfo.resultStatus != ResultStateType.INCOMPLETE:
				break
		
		return self.pcpResInfo

	def _process_error_response(self, toc, buf):
		"""
		For time we only support sev, error message and details
		"""

		errorSev = None
		errorMsg = None
		errorDet = None

		if toc != 'E' and toc != 'N':
			return

		parts = buf.split(b'\0')

		for part in parts:
			part = part.decode()
			if len(part) < 1:
				continue
			_type = part[0]
			if _type == 'M':
				errorMsg = part[1:]
			elif _type == 'S':
				errorSev = part[1:]
			elif _type == 'D':
				errorDet = part[1:]
		
		if not errorSev and not errorMsg:
			return

		if toc != 'E':				# This is not an error report it as debug
			if self.Pfdebug:
				self.Pfdebug.write(f'BACKEND {errorSev}:  {errorMsg}\n')
				if errorDet:
					self.Pfdebug.write(f'DETAIL:  {errorDet}\n')
		else:
			if errorDet:
				self.pcp_internal_error(f'{errorSev}:  {errorMsg}\nDETAIL:  {errorDet}\n')
			else:
				self.pcp_internal_error(f'{errorSev}:  {errorMsg}\n')
			self._setResultStatus(ResultStateType.BACKEND_ERROR)

	def pcp_disconnect(self):
		"""
		close connection to pgpool
		"""

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return
		
		self._PCPWrite('X'.encode(), 1)
		wsize = self.int_to_bytes(4)
		self._PCPWrite(wsize, 4)
		if self.PCPFlush() < 0:
			return
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="X", length={self.bytes_to_int(wsize)}\n')

		self.pcpConn.pcp_close()
		self.connState = ConnStateType.NOT_CONNECTED
		self.pcpConn = None

	def pcp_terminate_pgpool(self, mode, command_scope):
		"""
		send terminate packet\n
		return 0 on success, -1 otherwise
		"""

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None
		if command_scope == 'l': #local only
			self._PCPWrite('T'.encode(), 1)
		else:
			self._PCPWrite('t'.encode(), 1)
		wsize = self.int_to_bytes(4 + 1)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(mode.encode(), 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="T", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('T')

	def _process_pcp_node_count_response(self, buf, length):
		index = 0
		value, index = self._getNextString(buf, index)
		self.pcpResInfo.pcp_add_json_result('command_status', 'success')
		if value == 'CommandComplete':
			index += 1
			value, index = self._getNextString(buf, index)
			if value:
				ret = int(value)
				self.pcpResInfo.pcp_add_json_result('node_count', ret)
				self._setResultData(self.pcpResInfo, ret)
				self._setCommandSuccessful()
				return
			else:
				self.pcp_internal_error('command failed. invalid response')
		else:
			self.pcp_internal_error(f'command failed with reason: "{value}"')
		self.pcpResInfo.pcp_add_json_result('command_status', 'failed')
		self._setResultStatus(ResultStateType.BAD_RESPONSE)

	def pcp_node_count(self):
		"""
		get number of nodes currently connected to pgpool\n
		return array of node IDs on success, -1 otherwise
		"""

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None
		
		self._PCPWrite('L'.encode(), 1)
		wsize = self.int_to_bytes(4)
		self._PCPWrite(wsize, 4)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="L", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('L')

	def _process_node_info_response(self, buf, length):
		self.pcpResInfo.pcp_add_json_result('command_status', 'success')
		value, index = self._getNextString(buf, 0)

		if value and value == 'CommandComplete':
			index += 1
			backend_info = BackendInfo()

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				backend_info.backend_hostname = value

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				backend_info.backend_port = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				backend_info.backend_status = BACKEND_STATUS(int(value))

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				backend_info.backend_weight = float(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				backend_info.role = SERVER_ROLE(int(value))

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				backend_info.standby_delay = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				backend_info.replication_state = value
			index += 1

			value, index = self._getNextString(buf, index)
			if value:
				backend_info.replication_sync_state = value
			index += 1

			value, index = self._getNextString(buf, index)
			if value:
				backend_info.status_changed_time = int(value)
			index += 1

			self.pcpResInfo.pcp_add_json_result('node_info', backend_info.get_json())
			self._setResultData(self.pcpResInfo,  backend_info)
			self._setCommandSuccessful()
		else:
			self.pcp_internal_error(f'command failed with reason: "{buf}"')
			self.pcpResInfo.pcp_add_json_result('command_status', 'failed')
			self._setResultStatus(ResultStateType.BAD_RESPONSE)

	def pcp_node_info(self, nid):
		"""
		get information of node pointed by given argument\n
		return structure of node information on success, -1 otherwise
		"""

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None

		node_id = str(nid)

		self._PCPWrite('I'.encode(), 1)
		wsize = self.int_to_bytes(len(node_id) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(node_id.encode() + NULL, len(node_id) + 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="I", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('I')

	def _process_health_check_stats_response(self, buf, len):
		"""
		Process health check response from PCP server.\n
		pcpConn: connection to the server\n
		buf:		returned data from server\n
		len:		length of the data
		"""
		
		self.pcpResInfo.pcp_add_json_result('command_status', 'success')
		value, index = self._getNextString(buf, 0)

		if value and value == 'CommandComplete':
			index += 1
			
			stats = POOL_HEALTH_CHECK_STATS()

			for attrib in stats.attrib_list:
				value, index = self._getNextString(buf, index)
				if value:
					stats.add_stat(attrib, value)
				index += 1

			self.pcpResInfo.pcp_add_json_result('health_check_stats', stats.get_json())
			self._setResultData(self.pcpResInfo,  stats)
			self._setCommandSuccessful()
		else:
			self.pcp_internal_error(f'command failed with reason: "{buf}"')
			self.pcpResInfo.pcp_add_json_result('command_status', 'failed')
			self._setResultStatus(ResultStateType.BAD_RESPONSE)

	def pcp_health_check_stats(self, nid):
		"""
		pcp_health_check_stats - get information of health check stats pointed by given argument\n
		return structure of node information on success, -1 otherwise
		"""

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None

		node_id = str(nid)

		self._PCPWrite('H'.encode(), 1)
		wsize = self.int_to_bytes(len(node_id) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(node_id.encode() + NULL, len(node_id) + 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="H", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('H')

	def pcp_reload_config(self, command_scope):
		"""
		reload pgpool-II config file
		"""

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None

		self._PCPWrite('Z'.encode(), 1)
		wsize = self.int_to_bytes(4 + 1)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(command_scope.encode(), 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="Z", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('Z')

	def _process_process_count_response(self, buf, length):
		index = 0
		value, index = self._getNextString(buf, index)
		self.pcpResInfo.pcp_add_json_result('command_status', 'success')

		if value and value == 'CommandComplete':
			index +=1 
			process_count = 0

			value, index = self._getNextString(buf, index)
			if index == -1:
				self.pcp_internal_error('command failed. invalid response')
				self.pcpResInfo.pcp_add_json_result('command_status', 'failed')
				self._setResultStatus(ResultStateType.BAD_RESPONSE)
				return
			if value:
				index += 1
				process_count = int(value)

			self.pcpResInfo.pcp_add_json_result('process_count', process_count)
			pids = list()
			for i in range(process_count):
				value, index = self._getNextString(buf, index)
				if index == -1:
					self.pcp_internal_error('command failed. invalid response')
					self.pcpResInfo.pcp_add_json_result('command_status', 'failed')
					self._setResultStatus(ResultStateType.BAD_RESPONSE)
					return		
				index += 1
				pids.append(int(value))

			self.pcpResInfo.pcp_add_json_result('pids', pids)
			self._setResultData(self.pcpResInfo, pids)
			self._setCommandSuccessful()
		else:
			self.pcp_internal_error(f'command failed with reason: "{buf.decode()}"')
			self.pcpResInfo.pcp_add_json_result('command_status', 'failed')
			self._setResultStatus(ResultStateType.BAD_RESPONSE)

	def pcp_process_count(self):
		"""
		get number of nodes currently connected to pgpool\n
		return array of pids on success, None otherwise
		"""

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None
		
		self._PCPWrite('N'.encode(), 1)
		wsize = self.int_to_bytes(4)
		self._PCPWrite(wsize, 4)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="N", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('N')


	def _process_process_info_response(self, buf, length):
		value, index = self._getNextString(buf, 0)
		self.pcpResInfo.pcp_add_json_result('command_status', 'success')

		if value == 'ArraySize':
			index += 1
			value, index = self._getNextString(buf, index)
			if value:
				index += 1

			self._setResultStatus(ResultStateType.INCOMPLETE)
			self.pcpResInfo.pcp_add_json_result('process_info', list())
		elif value == 'ProcessInfo':
			index += 1
			if self.PCPResultStatus(self.pcpResInfo) != ResultStateType.INCOMPLETE:
				self.pcp_internal_error('command failed. invalid response')
				self._setResultStatus(ResultStateType.BAD_RESPONSE)

			processInfo = ProcessInfo()

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.pid = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.connection_info.database = value

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.connection_info.user = value

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.start_time = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.connection_info.create_time = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.connection_info.major = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.connection_info.minor = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.connection_info.counter = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.connection_info.backend_id = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.connection_info.pid = int(value)

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				processInfo.connection_info.connected = int(value)

			self.pcpResInfo.pcp_append_json_result('process_info', processInfo.get_json())
			self._setResultData(self.pcpResInfo,  processInfo)
		elif value == 'CommandComplete':
			self._setResultStatus(ResultStateType.COMMAND_OK)

	def pcp_process_info(self, pid):
		"""
		pcp_process_info - get information of node pointed by given argument\n
		return structure of process information on success, -1 otherwise
		"""
		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None

		process_id = str(pid)
		self._PCPWrite('P'.encode(), 1)
		wsize = self.int_to_bytes(len(process_id) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(process_id.encode() + NULL, len(process_id) + 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="P", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('P')

	def pcp_detach_node(self, nid):
		"""
		detach a node given by the argument from pgpool's control\n
		return 0 on success, -1 otherwise
		"""
		return self._pcp_detach_node(nid, False)

	def pcp_detach_node_gracefully(self, nid):
		"""
		detach a node given by the argument from pgpool's control\n
		return 0 on success, -1 otherwise
		"""
		return self._pcp_detach_node(nid, True)

	def _pcp_detach_node(self, nid, gracefully):
		sendchar = None

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None
		
		node_id = str(nid)

		if gracefully:
			sendchar = 'd'
		else:
			sendchar = 'D'

		self._PCPWrite(sendchar.encode(), 1)
		wsize = self.int_to_bytes(len(node_id) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(node_id.encode() + NULL, len(node_id) + 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="D", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('D')

	def _process_command_complete_response(self, buf, length):
		self.pcpResInfo.pcp_add_json_result('command_status', 'success')
		value, index = self._getNextString(buf, 0)
		index = 0
		if value == 'CommandComplete':
			self._setCommandSuccessful()	
		else:
			self.pcp_internal_error(f'command failed with reason: "{value}"')
			self.pcpResInfo.pcp_add_json_result('command_status', 'failed')
			self._setResultStatus(ResultStateType.BAD_RESPONSE)

	def pcp_attach_node(self, nid):
		"""
		attach a node given by the argument from pgpool's control\n
		return 0 on success, -1 otherwise
		"""
		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None
		
		node_id = str(nid)

		self._PCPWrite('C'.encode(), 1)
		wsize = self.int_to_bytes(len(node_id) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(node_id.encode() + NULL, len(node_id) + 1)
		if self.PCPFlush() < 0:
			return None

		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="C", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('C')

	def _process_pool_status_response(self, buf, length):
		"""
		return setup parameters and status\n
		returns and array of POOL_REPORT_CONFIG, None otherwise
		"""
		self.pcpResInfo.pcp_add_json_result('command_status', 'success')
		value, index = self._getNextString(buf, 0)
		if value == 'ArraySize':
			index += 1
			ci_size = buf[index:]
			ci_size = self.bytes_to_int(ci_size)

			self._setResultStatus(ResultStateType.INCOMPLETE)
			self.pcpResInfo.pcp_add_json_result('config', list())
		elif value == 'ProcessConfig':
			index += 1
			if self.PCPResultStatus(self.pcpResInfo) != ResultStateType.INCOMPLETE:
				self.pcp_internal_error('command failed. invalid response')
				self.pcpResInfo.pcp_add_json_result('command_status', 'failed')
				self._setResultStatus(ResultStateType.BAD_RESPONSE)

			status = POOL_REPORT_CONFIG()

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				status.name = value

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				status.value = value

			value, index = self._getNextString(buf, index)
			if value:
				index += 1
				status.desc = value

			self.pcpResInfo.pcp_append_json_result('config', status.get_json())
			self._setResultData(self.pcpResInfo,  status)
		elif value == 'CommandComplete':
			self._setResultStatus(ResultStateType.COMMAND_OK)

	def pcp_pool_status(self):

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None
		
		self._PCPWrite('B'.encode(), 1)
		wsize = self.int_to_bytes(4)
		self._PCPWrite(wsize, 4)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write('DEBUG self.pcp_pool_status: send: tos="B", length={self.bytes_to_int(wsize)}\n')
		return self._process_pcp_response('B')

	def pcp_recovery_node(self, nid):

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None
		
		node_id = str(nid)

		self._PCPWrite('O'.encode(), 1)
		wsize = self.int_to_bytes(len(node_id) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(node_id.encode() + NULL, len(node_id) + 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="D", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('O')

	def pcp_promote_node(self, nid):
		"""
		promote a node given by the argument as new pgpool's primary\n
		return 0 on success, -1 otherwise
		"""
		return self._pcp_promote_node(nid, False)

	def pcp_promote_node_gracefully(self, nid):
		"""
		promote a node given by the argument as new pgpool's primary\n
		return 0 on success, -1 otherwise
		"""
		return self._pcp_promote_node(nid, True)

	def _pcp_promote_node(self, nid, gracefully):
		sendchar = None

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None

		node_id = str(nid)

		if gracefully:
			sendchar = 'j'
		else:
			sendchar = 'J'

		self._PCPWrite(sendchar.encode(), 1)
		wsize = self.int_to_bytes(len(node_id) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(node_id.encode() + NULL, len(node_id) + 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="E", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('J')

	def _process_watchdog_info_response(self, buf, length):
		"""
		Get watchdog information
		"""
		json_data = None
		wd_cluster_info = None
		index = 0
		value, index = self._getNextString(buf, index)
		self.pcpResInfo.pcp_add_json_result('command_status', 'success')

		if value == 'CommandComplete':
			index  += 1
			tempVal = 0

			value, index = self._getNextString(buf, index)
			if value:
				json_data = value

			root  = None
			value = None

			try:
				root = json.loads(json_data)
				self.pcpResInfo.pcp_add_json_result('watchdog_info', root)
			except:
				pass
		
			nodeCount = root['NodeCount']
			wd_cluster_info = PCPWDClusterInfo()
			wd_cluster_info.nodeCount = nodeCount
			wd_cluster_info.remoteNodeCount = root[ 'RemoteNodeCount']
			wd_cluster_info.quorumStatus = root[ 'QuorumStatus']
			wd_cluster_info.aliveNodeCount = root[ 'AliveNodeCount']
			tempVal = root[ 'Escalated']
			if tempVal == 0:
				wd_cluster_info.escalated = False
			else:
				wd_cluster_info.escalated = True

			if 'LeaderNodeName' in root:
				wd_cluster_info.leaderNodeName = root[ 'LeaderNodeName']
				wd_cluster_info.leaderHostName = root[ 'LeaderHostName']
			else:
				wd_cluster_info.leaderNodeName = root[ 'MasterNodeName']
				wd_cluster_info.leaderHostName = root[ 'MasterHostName']

			#Get watchdog nodes data
			for nodeInfoValue in root[ 'WatchdogNodes']:
				wdNodeInfo = PCPWDNodeInfo()
				wdNodeInfo.id       = nodeInfoValue[ 'ID']
				wdNodeInfo.nodeName = nodeInfoValue[ 'NodeName']
				wdNodeInfo.hostName = nodeInfoValue[ 'HostName']
				wdNodeInfo.delegate_ip = nodeInfoValue[ 'DelegateIP']
				wdNodeInfo.wd_port     = nodeInfoValue[ 'WdPort']
				wdNodeInfo.pgpool_port = nodeInfoValue[ 'PgpoolPort']
				wdNodeInfo.state       = nodeInfoValue[ 'State']
				wdNodeInfo.stateName   = nodeInfoValue[ 'StateName']
				wdNodeInfo.wd_priority = nodeInfoValue[ 'Priority']
				wd_cluster_info.nodeList.append(wdNodeInfo)

			self._setResultData(self.pcpResInfo,  wd_cluster_info)
			self._setCommandSuccessful()
		else:
			self.pcp_internal_error(f'command failed with reason: "{value}"\n')
			self._setResultStatus(ResultStateType.BAD_RESPONSE)

	def pcp_watchdog_info(self, nid):
		"""
		get information of watchdog\n
		return structure of watchdog information on success, None otherwise
		"""
		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None
		
		wd_index = str(nid)
		self._PCPWrite('W'.encode(), 1)
		wsize = self.int_to_bytes(len(wd_index) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(wd_index.encode() + NULL, len(wd_index) + 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="W", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('W')

	def pcp_set_backend_parameter(self, parameter_name, value):
		"""
		Set pgpool configuration parameter
		"""

		if self.PCPConnectionStatus() != ConnStateType.OK:
			self.pcp_internal_error('invalid PCP connection')
			return None
		
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: seting: "{parameter_name} = {value}"\n')

		self._PCPWrite('A'.encode(), 1)
		wsize = self.int_to_bytes(len(parameter_name) + 1 + len(value) + 1 + 4)
		self._PCPWrite(wsize, 4)
		self._PCPWrite(parameter_name.encode(), len(parameter_name))
		self._PCPWrite(NULL, 1)
		self._PCPWrite(value.encode(), len(value))
		self._PCPWrite(NULL, 1)
		if self.PCPFlush() < 0:
			return None
		if self.Pfdebug:
			self.Pfdebug.write(f'DEBUG: send: tos="A", length={self.bytes_to_int(wsize)}\n')

		return self._process_pcp_response('A')

	def pcp_internal_error(self, msg):
		"""
		produce an internally-generated notice message\n
		The supplied text is taken as primary message (ie., it should not include\n
		a trailing newline, and should not be more than one line).
		"""
		if self.errMsg:
			del self.errMsg

		self.errMsg = msg

	def PCPConnectionStatus(self):
		if not self.pcpConn:
			return ConnStateType.BAD
		return self.connState

	def PCPResultStatus(self, res):
		if not res:
			return ResultStateType.ERROR
		return res.resultStatus

	def _setResultStatus(self, resultState):
		if self.pcpResInfo:
			self.pcpResInfo.resultStatus = resultState

	def _setCommandSuccessful(self):
		self._setResultStatus(ResultStateType.COMMAND_OK)
		
	def _setResultData(self, res, value):
		res.pcp_add_result(value)

	def _PCPWrite(self, _data, _len):
		self.pcpConn.pcp_write(_data, _len)

	def _PCPRead(self, _len):
		return self.pcpConn.pcp_read(_len)

	def PCPFlush(self):
		ret = self.pcpConn.pcp_flush()
		if ret:
			self.pcp_internal_error(f'ERROR: sending data to backend failed with error "{ret}"')
			return -1
		return 0

	def pcp_free_result(self):
		if self.pcpResInfo:
			del self.pcpResInfo
			self.pcpResInfo = None

	def pcp_get_last_error(self):
		return self.errMsg

	def _getPoolPassFilename(self, ):
		"""
		get the password file name which could be either pointed by PCPPASSFILE\n
		environment variable or resides in user home directory.
		"""
		pgpassfile = None

		passfile_env = os.getenv('PCPPASSFILE', None)
		if passfile_env != None:
			# use the literal path from the environment, if set
			pgpassfile = passfile_env	
		else:
			homedir = str(Path.home())
			pgpassfile = os.path.join(homedir, PCPPASSFILE)
		
		return pgpassfile

	def _PasswordFromFile(self, hostname, port, username):
		"""
		Get a password from the password file. Return value is malloc'd.\n
		format = hostname:port:username:password
		"""

		if username == None or len(username) == 0:
			return None

		if hostname == None or hostname == UNIX_DOMAIN_PATH:
			hostname = DefaultHost

		pgpassfile = self._getPoolPassFilename()
		if not os.path.exists(pgpassfile):
			if self.Pfdebug:
				self.Pfdebug.write(f'WARNING: password file "{pgpassfile}" does not exist\n')
			return None

		# If password file cannot be opened, ignore it.
		stat_buf = None
		try:
			stat_buf = os.stat(pgpassfile)
		except Exception:
			return None

		st_mode = stat_buf.st_mode
		if not stat.S_ISREG(st_mode):
			if self.Pfdebug:
				self.Pfdebug.write(f'WARNING: password file "{pgpassfile}" is not a plain file\n')
			return None
		
		# If password file is insecure, alert the user and ignore it.
		if stat.S_IRWXG & st_mode or stat.S_IRWXO & st_mode:
			if self.Pfdebug:
				self.Pfdebug.write(f'WARNING: password file "{pgpassfile}" has group or world access; permissions should be u=rw (0600) or less\n')
			return None
		
		fp = open(pgpassfile, 'r')
		if fp == None:
			return None

		for line in fp:
			#Remove trailing newline
			line = line.strip('\n')
			if 0 == len(line):
				continue
			parts = re.split('[^\\\\]:', line)
			if len(parts) < 4:
				print('Warning: Invalid pgpass entry')
				continue
			if parts[0] == hostname and parts[1] == port and parts[2] ==  username:
				# Deescape password
				last_part = parts[3].replace('\\','')
				fp.close()
				return last_part
		fp.close()
		return None

	def int_to_bytes(self, value):
		# ntohl ?
		return (value).to_bytes(4, 'big')
	
	def bytes_to_int(self, value):
		# htonl ?
		return int.from_bytes(value, 'big')

	def _getNextToken(self, buf, index=0):
		last_index = index
		if index != -1:
			index = buf[index:].find(b'\0')
		value = None
		if index != -1:
			value = buf[last_index:last_index+index]
			index += last_index
		return value, index

	def _getNextString(self, buf, index=0):
		value, index = self._getNextToken(buf, index)
		if value:
			value = value.decode()
		return value, index

class PCPWDNodeInfo:

	def __init__(self):
		self.state     = -1
		self.nodeName  = ''
		self.hostName  = ''	    # host name
		self.stateName = ''     # state name
		self.wd_port   = -1		# watchdog port
		self.wd_priority = -1	# node priority in leader election
		self.pgpool_port = -1	# pgpool port
		self.delegate_ip = ''	# delegate IP
		self.id = -1

class PCPWDClusterInfo:

	def __init__(self):
		self.remoteNodeCount = -1
		self.quorumStatus = -1
		self.aliveNodeCount = -1
		self.escalated = None
		self.leaderNodeName = ''
		self.leaderHostName = ''
		self.nodeCount = -1    # -> int
		self.nodeList = list() # -> PCPWDNodeInfo

class BACKEND_STATUS(Enum):
	CON_UNUSED = 0					# unused slot
	CON_CONNECT_WAIT = 1			# waiting for connection starting
	CON_UP = 2						# up and running
	CON_DOWN = 3					# down, disconnected

	def __str__(self):
		role_str = ['unused', 'waiting', 'up', 'down']
		if self.value < 0 or self.value > 3:
			return 'unknown'
		return role_str[self.value]

class SERVER_ROLE(Enum):
	MAIN    = 1
	REPLICA   = 2
	PRIMARY = 3
	STANDBY = 4

	def __str__(self):
		role_str = ['main', 'replica', 'primary', 'standby']
		if self.value < 1 or self.value > 4:
			return 'unknown'
		return role_str[self.value]

class ConnStateType(Enum):
	OK = 1
	CONNECTED = 2
	NOT_CONNECTED = 3
	BAD = 4
	AUTH_ERROR = 5

class ResultStateType(Enum):
	COMMAND_OK = 1
	BAD_RESPONSE = 2
	BACKEND_ERROR = 3
	INCOMPLETE = 4
	ERROR = 5

class BackendInfo:
	"""
	PostgreSQL backend descriptor.
	"""

	def __init__(self):
		self.backend_hostname = ''	# backend host name
		self.backend_port = -1		# backend port numbers
		self.backend_status = None	# backend status
		self.status_changed_time = None	# backend status changed time
		self.backend_weight = None 		# normalized backend load balance ratio
		self.quarantine = True		# true if node is CON_DOWN because of
									# quarantine
		self.standby_delay=-1		# The replication delay against the primary
		self.srole = None			# Role of server. used by pcp_node_info and
									# failover() to keep track of quarantined
									# primary node
		self.replication_state = ''	# "state" from pg_stat_replication
		self.replication_sync_state = ''	# "sync_state" from pg_stat_replication

	def get_json(self):
		result = dict()
		result['backend_hostname'] = self.backend_hostname
		result['backend_port'] = self.backend_port
		result['backend_status'] = self.backend_status
		result['status_changed_time'] = self.status_changed_time
		result['backend_weight'] = self.backend_weight
		result['standby_delay'] = self.standby_delay
		result['role'] = self.srole
		result['standby_delay'] = self.standby_delay
		result['replication_state'] = self.replication_state
		result['replication_sync_state'] = self.replication_sync_state
		return result

class ConnectionInfo:
	"""
	Connection pool information.
	"""

	def __init__(self):
		self.backend_id = -1	# backend id
		self.database = ''	    # Database name
		self.user = ''	        # User name
		self.major = -1			# protocol major version
		self.minor = -1			# protocol minor version
		self.pid = -1			# backend process id
		self.counter = -1		# used counter
		self.create_time = None	# connection creation time
		self.load_balancing_node = -1	# load balancing node
		self.connected = None		# True if frontend connected. 

	def get_json(self):
		result = dict()
		result['backend_id'] = self.backend_id
		result['database'] = self.database
		result['user'] = self.user
		result['major'] = self.major
		result['minor'] = self.minor
		result['pid'] = self.pid
		result['counter'] = self.counter
		result['create_time'] = self.create_time
		result['load_balancing_node'] = self.load_balancing_node
		result['connected'] = self.connected
		return result

class ProcessInfo:
	"""
	process information
	"""

	def __init__(self):
		self.pid = None				# OS's process id
		self.start_time = None		# fork() time
		self.connection_info = ConnectionInfo()	# head of the connection info for
									# this process

	def get_json(self):
		result = dict()
		result['pid'] = self.pid
		result['start_time'] = self.start_time
		result['connection_info'] = self.connection_info.get_json()
		return result
	
	def __del__(self):
		if self.connection_info:
			del self.connection_info

class POOL_REPORT_CONFIG:
	"""
	config report struct
	"""

	def __init__(self):
		self.name  = ''
		self.value = ''
		self.desc  = ''
	
	def __str__(self):
		return f'Name : {self.name}\nValue: {self.value}\nDesc: {self.desc}'
	
	def get_json(self):
		result = dict()
		result['name'] = self.name
		result['value'] = self.value
		result['desc'] = self.desc
		return result

class PCPResultInfo:
	"""
	PCPResultInfo
	"""

	def __init__(self):
		self.resultStatus = None # -> ResultStateType
		self.results = list()
		self.results_json = dict()
	
	def pcp_add_result(self, result):
		self.results.append(result)

	def pcp_add_json_result(self, key, result):
		self.results_json[key]= result

	def pcp_append_json_result(self, key, result):
		if type(self.results_json[key]) == list:
			self.results_json[key].append(result)

	def pcp_result_is_empty(self):
		"""
		Returns 1 if ResultInfo has no data. 0 otherwise
		"""
		return len(self.results) == 0

	def pcp_get_data(self, slotno):
		return self.results[slotno]

	def pcp_get_json_data(self):
		return self.results_json
	
	def __del__(self):
		self.results.clear()
		self.results_json.clear()

	def __str__(self):
		return f'PCPResultInfo: Status:{self.resultStatus} ResultCount:{len(self.results)}'

class POOL_HEALTH_CHECK_STATS:
	"""
	health check statistics report struct
	"""
	
	def __init__(self):
		self.attrib_list = ['node_id', 'hostname', 'port', 'status', 'role', 'last_status_change',
							'total_count', 'success_count', 'fail_count', 'skip_count', 'retry_count',
							'average_retry_count', 'max_retry_count', 'max_health_check_duration',
							'min_health_check_duration', 'average_health_check_duration',
							'last_health_check', 'last_successful_health_check', 'last_successful_health_check',
							'last_skip_health_check', 'last_failed_health_check']
		self.attrib_map = dict()
		self.attrib_map['node_id'] = ''
		self.attrib_map['hostname'] = ''
		self.attrib_map['port'] = ''
		self.attrib_map['status'] = ''
		self.attrib_map['role'] = ''
		self.attrib_map['last_status_change'] = ''
		self.attrib_map['total_count'] = ''
		self.attrib_map['success_count'] = ''
		self.attrib_map['fail_count'] = ''
		self.attrib_map['skip_count'] = ''
		self.attrib_map['retry_count'] = ''
		self.attrib_map['average_retry_count'] = ''
		self.attrib_map['max_retry_count'] = ''
		self.attrib_map['max_health_check_duration'] = ''
		self.attrib_map['min_health_check_duration'] = ''
		self.attrib_map['average_health_check_duration'] = ''
		self.attrib_map['last_health_check'] = ''
		self.attrib_map['last_successful_health_check'] = ''
		self.attrib_map['last_skip_health_check'] = ''
		self.attrib_map['last_failed_health_check'] = ''

	def add_stat(self, attrib, value):
		self.attrib_map[attrib] = value

	def __getitem__(self, key):
		return self.attrib_map[key]
	
	def get_json(self):
		return self.attrib_map

