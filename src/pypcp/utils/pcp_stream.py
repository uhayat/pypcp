
READBUFSZ  = 1024
WRITEBUFSZ = 8192
UNIX_DOMAIN_PATH = '/tmp'

class PCP_CONNECTION:

	def __init__(self):
		self.fd = -1				# fd for connection
		self.wbuf =b''				# write buffer for the connection

	def pcp_open(self, fd):
		"""
		pcp_open - allocate read & write buffers for PCP_CONNECTION\n
		return newly allocated PCP_CONNECTION on success, NULL if malloc() fails
		"""

		# initialize write buffer
		self.wbuf = b''
		self.fd = fd

	def pcp_close(self):
		"""
		pcp_close - deallocate read & write buffers for PCP_CONNECTION
		"""
		
		self.fd.close()
		del self.wbuf

	def pcp_read(self, _len):
		"""
		pcp_read - read '_len' bytes from 'pc'\n
		return 0 on success, -1 otherwise
		"""

		#print('pcp_read', _len)
		readbuf = self.fd.recv(_len)
		#print('pcp_read readbuf', readbuf)
		return readbuf

	def pcp_write(self, buf, _len):
		"""
		pcp_write - write '_len' bytes to 'pc' buffer\n
		return 0 on success, -1 otherwise
		"""
		#print('pcp_write ', buf)

		if (_len < 0):
			return -1

		#print('pcp_write before wbuf ', self.wbuf)
		#print('pcp_write before len ', len(self.wbuf))
		self.wbuf += buf
		#print('pcp_write after wbuf ', self.wbuf)
		#print('pcp_write after len ', len(self.wbuf))

		return 0

	def pcp_flush(self):
		"""
		pcp_flush - send pending data in buffer to 'pc'\n
		return 0 on success, -1 otherwise
		"""

		#print('pcp_flush wlen ',len(self.wbuf))
		wlen = len(self.wbuf)
		if (wlen == 0):
			return 0
		try:
			#print('pcp_flush data',self.wbuf)
			self.fd.sendall(self.wbuf)
			self.wbuf = b''
		except Exception as e:
			return e

		return None
