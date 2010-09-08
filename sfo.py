from Struct import Struct
import struct
import sys

def nullterm(str_plus):
	z = str_plus.find('\0')
	if z != -1:
		return str_plus[:z]
	else:
		return str_plus

class Header(Struct):
	__endian__ = Struct.LE
	def __format__(self):
		self.magic = Struct.uint32
		self.unk1 = Struct.uint32
		self.KeyOffset = Struct.uint32
		self.ValueOffset = Struct.uint32
		self.PairCount = Struct.uint32
	def __str__(self):
		out  = ""
		out += "[X] Magic: %08x\n" % self.magic
		out += "[ ] Unk1: %08x\n" % self.unk1
		out += "[X] Key Offset: %08x\n" % self.KeyOffset
		out += "[X] Value Offset: %08x\n" % self.ValueOffset
		out += "[X] Pair Count: %08x" % self.PairCount
		return out

class Entry(Struct):
	__endian__ = Struct.LE
	def __format__(self):
		self.key_off   = Struct.uint16
		self.unk1      = Struct.uint8
		self.value_type      = Struct.uint8
		self.value_len      = Struct.uint32
		self.str_len   = Struct.uint32
		self.value_off = Struct.uint32
	def __str__(self):
		out  = ""
		out += "[X] Key Offset: %04x\n" % self.key_off
		out += "[ ] Unk1: %02x\n" % self.unk1
		out += "[/] Value Type: %02x\n" % self.value_type
		out += "[X] Value Length: %08x\n" % self.value_len
		out += "[X] String Length: %08x\n" % self.str_len
		out += "[X] Value Offset: %08x" % self.value_off
		return out
	def PrettyPrint(self, data, key_off, value_off):
		out  = ""
		out += "[X] Key: '%s'[%04x]\n" % (nullterm(data[self.key_off + key_off:]), self.key_off)
		out += "[/] Unks: %02x %02x\n" % (self.unk1,self.value_type)
		out += "[X] Value Length: %08x\n" % self.value_len
		if self.value_type == 0x2:
			out += "[X] Value: '%s'[%08x]" % (nullterm(data[self.value_off + value_off:self.value_off + value_off + self.str_len]), self.value_off+value_off)
		elif self.value_type == 0x4:
			out += "[X] Value: %d[%08x]" % (struct.unpack('<I', data[self.value_off + value_off:self.value_off + value_off + self.str_len])[0], self.value_off+value_off)
		else:
			out += "[X] Value Type Unknown"
		return out

def main():
	debug = False
	pretty = False
	if "--debug" in sys.argv:
		debug = True
	if "--pretty" in sys.argv:
		pretty = True
	with open(sys.argv[1], 'rb') as fp:
		stuff = {}
		data = fp.read()
		offset = 0
		header = Header()
		header.unpack(data[offset:offset+len(header)])
		if debug:
			print header
			print
		assert header.magic == 0x46535000
		assert header.unk1 == 0x00000101
		offset += len(header)
		off1 = header.KeyOffset
		off2 = header.ValueOffset
		for x in xrange(header.PairCount):
			entry = Entry()
			entry.unpack(data[offset:offset+len(entry)])
			if debug and not pretty:
				print entry
				print
			if debug and pretty:
				print entry.PrettyPrint(data, off1, off2)
				print
			key = nullterm(data[off1+entry.key_off:])
			if entry.value_type == 2:
				value = nullterm(data[off2+entry.value_off:off2+entry.value_off+entry.str_len])
			else:
				value = struct.unpack('<I', data[entry.value_off + off2:entry.value_off + off2 + entry.str_len])[0]
			stuff[key] = value
			offset += len(entry)
		if not debug:
			print stuff

if __name__ == "__main__":
	main()
