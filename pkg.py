from Struct import Struct
import struct
import sys
import hashlib
import os

class FileHeader(Struct):
	__endian__ = Struct.BE
	def __format__(self):
		self.fileNameOff 	= Struct.uint32
		self.fileNameLength = Struct.uint32
		self.unk1 			= Struct.uint32
		self.fileOff 		= Struct.uint32
		
		self.unk2		= Struct.uint32
		self.fileSize 	= Struct.uint32
		self.flags		= Struct.uint32
		self.unk3 		= Struct.uint32
	def __str__(self):
		out  = ""
		out += "[X] File Name: %s [" % self.fileName
		if self.flags & 0xFF == 1:
			out += "NPDRM Self]\n"
		elif self.flags & 0xFF == 4:
			out += "Directory]\n"
		elif self.flags & 0xFF == 3:
			out += "Raw Data]\n"
		else:
			out += "Unknown\n"
		out += "\n"
		out += "[X] File Name offset: %08x\n" % self.fileNameOff
		out += "[X] File Name Length: %08x\n" % self.fileNameLength
		out += "[ ] Unk1: %08x\n" % self.unk1
		out += "[X] Offset To File Data: %08x\n" % self.fileOff
		
		out += "[ ] Unk2: %08x\n" % self.unk2
		out += "[X] File Size: %08x\n" % self.fileSize
		out += "[X] Flags: %08x\n" % self.flags
		out += "[ ] Unk3: %08x\n\n" % self.unk3
		
		
		
		return out
	def __init__(self):
		Struct.__init__(self)
		self.fileName = ""
	def doWork(self, decrypteddata):
		self.fileName = nullterm(decrypteddata[self.fileNameOff:self.fileNameOff+self.fileNameLength])
	def dump(self, directory, data, header):
		if self.flags & 0xFF == 0x4:
			try:
				os.makedirs(directory + "/" + self.fileName)
			except Exception:
				print
			
		else:
			tFile = open(directory + "/" + self.fileName, "wb")
			tFile.write(data[self.fileOff:self.fileOff+self.fileSize])
			

class Header(Struct):
	__endian__ = Struct.BE
	def __format__(self):
		self.magic = Struct.uint32
		self.type = Struct.uint32
		self.pkgInfoOff = Struct.uint32
		self.unk2 = Struct.uint32
		
		self.headSize = Struct.uint32
		self.itemCount = Struct.uint32
		self.unk4 = Struct.uint32
		self.packageSize = Struct.uint32
		
		self.dataOff = Struct.uint64
		self.dataSize = Struct.uint64
		
		self.contentID = Struct.uint8[0x30]
		self.QADigest = Struct.uint8[0x10]
		self.UnkDigest = Struct.uint8[0x10]
		
		
		
	def __str__(self):
		out  = ""
		out += "[X] Magic: %08x\n" % self.magic
		out += "[X] Type: %08x\n" % self.type
		out += "[X] Offset to package info: %08x\n" % self.pkgInfoOff
		out += "[ ] Unk2: %08x\n" % self.unk2
		
		out += "[X] Head Size: %08x\n" % self.headSize
		out += "[X] Item Count: %08x\n" % self.itemCount
		out += "[ ] Unk4: %08x\n" % self.unk4
		out += "[X] Package Size: %08x\n" % self.packageSize
		
		out += "[X] Data Offset: %016x\n" % self.dataOff
		out += "[X] Data Size: %016x\n" % self.dataSize
		
		out += "[X] ContentID: '%s'\n" % (nullterm(self.contentID))
		
		out += "[X] QA_Digest: %s\n" % (nullterm(self.QADigest, True))
		out += "[ ] Unk_Digest: %s\n" % (nullterm(self.UnkDigest, True))
		
		
		return out
def listToString(inlist):
	if isinstance(inlist, list):
		return ''.join(["%c" % el for el in inlist])
	else:
		return ""
def nullterm(str_plus, printhex=False):
	if isinstance(str_plus, list):
		if printhex:
			str_plus = ''.join(["%X" % el for el in str_plus])
		else:
			str_plus = listToString(str_plus)
	z = str_plus.find('\0')
	if z != -1:
		return str_plus[:z]
	else:
		return str_plus
		
def keyToContext(key):
	if isinstance(key, list):
		key = listToString(key)
		key = key[0:16]
	largekey = []
	for i in range(0, 8):
		largekey.append(ord(key[i]))
	for i in range(0, 8):
		largekey.append(ord(key[i]))
	for i in range(0, 8):
		largekey.append(ord(key[i+8]))
	for i in range(0, 8):
		largekey.append(ord(key[i+8]))
	for i in range(0, 0x20):
		largekey.append(0)
	return largekey

#Thanks to anonymous for the help with the RE of this part,
# the x86 mess of ands and ors made my head go BOOM headshot.
def manipulate(key):
	if not isinstance(key, list):
		return
	tmp = listToString(key[0x38:])
	
	
	tmpnum = struct.unpack('>Q', tmp)[0]
	tmpnum += 1
	tmpchrs = struct.pack('>Q', tmpnum)
	
	key[0x38] = ord(tmpchrs[0])
	key[0x39] = ord(tmpchrs[1])
	key[0x3a] = ord(tmpchrs[2])
	key[0x3b] = ord(tmpchrs[3])
	key[0x3c] = ord(tmpchrs[4])
	key[0x3d] = ord(tmpchrs[5])
	key[0x3e] = ord(tmpchrs[6])
	key[0x3f] = ord(tmpchrs[7])
def crypt(key, inbuf, length):
	if not isinstance(key, list):
		return ""
	ret = ""
	offset = 0
	while length > 0:
		bytes_to_dump = length
		if length > 0x10:
			bytes_to_dump = 0x10
		outhash = SHA1(listToString(key)[0:0x40])
		for i in range(0, bytes_to_dump):
			ret += chr(ord(outhash[i]) ^ ord(inbuf[offset]))
			offset += 1
		manipulate(key)
		length -= bytes_to_dump
	return ret
def SHA1(data):
	m = hashlib.sha1()
	m.update(data)
	return m.digest()
	
def main():
	debug = False
	pretty = False
	if "--debug" in sys.argv:
		debug = True
	if "--pretty" in sys.argv:
		pretty = True
	with open(sys.argv[1], 'rb') as fp:
		data = fp.read()
		offset = 0
		header = Header()
		header.unpack(data[offset:offset+len(header)])
		if debug:
			print header
			print
		
		if header.itemCount > 0:
			dataEnc = data[header.dataOff:header.dataOff+header.dataSize]
			context = keyToContext(header.QADigest)
			
			decData = crypt(context, dataEnc, header.dataSize)
			
			try:
				os.makedirs("OUTFILE")
			except Exception:
				pass
			fileDescs = []
			for i in range(0, header.itemCount):
				fileD = FileHeader()
				fileD.unpack(decData[0x20 * i:0x20 * i + 0x20])
				fileD.doWork(decData)
				fileDescs.append(fileD)
				print fileD
				#context = keyToContext(header.QADigest)
				fileD.dump("OUTFILE", decData, header)
				
				
	
	#with open("keycontext.bin", 'rb') as fp:
	#	contents = fp.read()
	#	m = hashlib.sha1()
	#	m.update(contents)
	#	print m.hexdigest()
	#	print crypt(contents, )
if __name__ == "__main__":
	main()
