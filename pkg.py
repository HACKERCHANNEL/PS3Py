from Struct import Struct
import struct
import sys
import hashlib

class Header(Struct):
	__endian__ = Struct.BE
	def __format__(self):
		self.magic = Struct.uint32
		self.unk1 = Struct.uint32
		self.off1 = Struct.uint32
		self.unk2 = Struct.uint32
		
		self.unk3 = Struct.uint32
		self.itemCount = Struct.uint32
		self.unk4 = Struct.uint32
		self.packageSize = Struct.uint32
		
		self.unk5 = Struct.uint32
		self.off2 = Struct.uint32
		self.unk6 = Struct.uint32
		self.unk7 = Struct.uint32
		
		self.contentID = Struct.uint8[0x30]
		self.QADigest = Struct.uint8[0x10]
		self.UnkDigest = Struct.uint8[0x10]
		
		
		
	def __str__(self):
		out  = ""
		out += "[X] Magic: %08x\n" % self.magic
		out += "[ ] Unk1: %08x\n" % self.unk1
		out += "[ ] Unk Offset1: %08x\n" % self.off1
		out += "[ ] Unk2: %08x\n" % self.unk2
		
		out += "[ ] Unk3: %08x\n" % self.unk3
		out += "[X] Item Count: %08x\n" % self.itemCount
		out += "[ ] Unk4: %08x\n" % self.unk4
		out += "[X] Package Size: %08x\n" % self.packageSize
		
		out += "[ ] Unk5: %08x\n" % self.unk5
		out += "[ ] Unk Offset2: %08x\n" % self.off2
		out += "[ ] Unk6: %08x\n" % self.unk6
		out += "[ ] Unk7: %08x\n" % self.unk7
		
		out += "[X] ContentID: '%s'\n" % (nullterm(self.contentID))
		
		out += "[X] QA_Digest: %s\n" % (nullterm(self.QADigest, True))
		out += "[ ] Unk_Digest: %s\n" % (nullterm(self.UnkDigest, True))
		
		
		return out
		
def nullterm(str_plus, printhex=False):
	if isinstance(str_plus, list):
		if printhex:
			str_plus = ''.join(["%X" % el for el in str_plus])
		else:
			str_plus = ''.join(["%c" % el for el in str_plus])
	z = str_plus.find('\0')
	if z != -1:
		return str_plus[:z]
	else:
		return str_plus
def crypt(keycontext, outbuf, inbuf, length):
	return ""
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
	
	#with open("keycontext.bin", 'rb') as fp:
	#	contents = fp.read()
	#	m = hashlib.sha1()
	#	m.update(contents)
	#	print m.hexdigest()
	#	print crypt(contents, )
if __name__ == "__main__":
	main()
