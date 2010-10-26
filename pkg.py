#!/usr/bin/env python
from __future__ import with_statement
from Struct import Struct
from fself import SelfHeader, AppInfo

import struct
import sys
import hashlib
import os
import getopt
import ConfigParser
import io
import glob

TYPE_NPDRMSELF = 0x1
TYPE_RAW = 0x3
TYPE_DIRECTORY = 0x4

TYPE_OVERWRITE_ALLOWED = 0x80000000

debug = False

class EbootMeta(Struct):
	__endian__ = Struct.BE
	def __format__(self):
		self.magic 			= Struct.uint32
		self.unk1 			= Struct.uint32
		self.drmType 		= Struct.uint32
		self.unk2			= Struct.uint32
		self.contentID 		= Struct.uint8[0x30]
		self.fileSHA1 		= Struct.uint8[0x10]
		self.notSHA1 		= Struct.uint8[0x10]
		self.notXORKLSHA1 	= Struct.uint8[0x10]
		self.nulls 			= Struct.uint8[0x10]
class MetaHeader(Struct):
	__endian__ = Struct.BE
	def __format__(self):
		self.unk1 	= Struct.uint32
		self.unk2 	= Struct.uint32
		self.drmType 	= Struct.uint32
		self.unk4 	= Struct.uint32
		
		self.unk21 	= Struct.uint32
		self.unk22 	= Struct.uint32
		self.unk23 	= Struct.uint32
		self.unk24 	= Struct.uint32
		
		self.unk31 	= Struct.uint32
		self.unk32 	= Struct.uint32
		self.unk33 	= Struct.uint32
		self.secondaryVersion 	= Struct.uint16
		self.unk34 	= Struct.uint16
		
		self.dataSize 	= Struct.uint32
		self.unk42 	= Struct.uint32
		self.unk43 	= Struct.uint32
		self.packagedBy 	= Struct.uint16
		self.packageVersion 	= Struct.uint16
class DigestBlock(Struct):
	__endian__ = Struct.BE
	def __format__(self):
		self.type 	= Struct.uint32
		self.size 	= Struct.uint32
		self.isNext = Struct.uint64
class FileHeader(Struct):
	__endian__ = Struct.BE
	def __format__(self):
		self.fileNameOff 	= Struct.uint32
		self.fileNameLength = Struct.uint32
		self.fileOff 		= Struct.uint64
		
		self.fileSize 	= Struct.uint64
		self.flags		= Struct.uint32
		self.padding 		= Struct.uint32
	def __str__(self):
		out  = ""
		out += "[X] File Name: %s [" % self.fileName
		if self.flags & 0xFF == TYPE_NPDRMSELF:
			out += "NPDRM Self]"
		elif self.flags & 0xFF == TYPE_DIRECTORY:
			out += "Directory]"
		elif self.flags & 0xFF == TYPE_RAW:
			out += "Raw Data]"
		else:
			out += "Unknown]"
		if (self.flags & TYPE_OVERWRITE_ALLOWED ) != 0:
			out += " Overwrite allowed.\n"
		else:
			out += " Overwrite NOT allowed.\n"
		out += "\n"
		
		out += "[X] File Name offset: %08x\n" % self.fileNameOff
		out += "[X] File Name Length: %08x\n" % self.fileNameLength
		out += "[X] Offset To File Data: %016x\n" % self.fileOff
		
		out += "[X] File Size: %016x\n" % self.fileSize
		out += "[X] Flags: %08x\n" % self.flags
		out += "[X] Padding: %08x\n\n" % self.padding
		assert self.padding == 0, "I guess I was wrong, this is not padding."
		
		
		return out
	def __repr__(self):
		return self.fileName + ("<FileHeader> Size: 0x%016x" % self.fileSize)
	def __init__(self):
		Struct.__init__(self)
		self.fileName = ""
	def doWork(self, decrypteddata, context = None):
		if context == None:
			self.fileName = nullterm(decrypteddata[self.fileNameOff:self.fileNameOff+self.fileNameLength])
		else:
			self.fileName = nullterm(crypt(context, decrypteddata[self.fileNameOff:self.fileNameOff+self.fileNameLength], self.fileNameLength))
	def dump(self, directory, data, header):
		if self.flags & 0xFF == 0x4:
			try:
				os.makedirs(directory + "/" + self.fileName)
			except Exception, e:
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
		self.unk1 = Struct.uint32
		
		self.headSize = Struct.uint32
		self.itemCount = Struct.uint32
		self.packageSize = Struct.uint64
		
		self.dataOff = Struct.uint64
		self.dataSize = Struct.uint64
		
		self.contentID = Struct.uint8[0x30]
		self.QADigest = Struct.uint8[0x10]
		self.KLicensee = Struct.uint8[0x10]
		
		
		
	def __str__(self):
		context = keyToContext(self.QADigest)
		setContextNum(context, 0xFFFFFFFFFFFFFFFF)
		licensee = crypt(context, listToString(self.KLicensee), 0x10)
		
		out  = ""
		out += "[X] Magic: %08x\n" % self.magic
		out += "[X] Type: %08x\n" % self.type
		out += "[X] Offset to package info: %08x\n" % self.pkgInfoOff
		out += "[ ] unk1: %08x\n" % self.unk1
		
		out += "[X] Head Size: %08x\n" % self.headSize
		out += "[X] Item Count: %08x\n" % self.itemCount
		out += "[X] Package Size: %016x\n" % self.packageSize
		
		out += "[X] Data Offset: %016x\n" % self.dataOff
		out += "[X] Data Size: %016x\n" % self.dataSize
		
		out += "[X] ContentID: '%s'\n" % (nullterm(self.contentID))
		
		out += "[X] QA_Digest: %s\n" % (nullterm(self.QADigest, True))
		out += "[X] K Licensee: %s\n" % licensee.encode('hex')
		
		
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
	tmpnum = tmpnum & 0xFFFFFFFFFFFFFFFF
	setContextNum(key, tmpnum)
def setContextNum(key, tmpnum):
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
	
def listPkg(filename):
	with open(filename, 'rb') as fp:
		data = fp.read()
		offset = 0
		header = Header()
		header.unpack(data[offset:offset+len(header)])
		print header
		print
		
		assert header.type == 0x00000001, 'Unsupported Type'
		if header.itemCount > 0:
			print 'Listing: "' + filename + '"'
			print "+) overwrite, -) no overwrite"
			print
			dataEnc = data[header.dataOff:header.dataOff+header.dataSize]
			context = keyToContext(header.QADigest)
			
			decData = crypt(context, dataEnc, len(FileHeader())*header.itemCount)
			
			fileDescs = []
			for i in range(0, header.itemCount):
				fileD = FileHeader()
				fileD.unpack(decData[0x20 * i:0x20 * i + 0x20])
				fileDescs.append(fileD)
			for fileD in fileDescs:
				fileD.doWork(dataEnc, context)
				out = ""
				if fileD.flags & 0xFF == TYPE_NPDRMSELF:
					out += " NPDRM SELF:"
				elif fileD.flags & 0xFF == TYPE_DIRECTORY:
					out += "  directory:"
				elif fileD.flags & 0xFF == TYPE_RAW:
					out += "   raw data:"
				else:
					out += "    unknown:"
				if (fileD.flags & TYPE_OVERWRITE_ALLOWED ) != 0:
					out += "+"
				else:
					out += "-"
				out += "%11d: " % fileD.fileSize
				out += fileD.fileName
				print out,
				print
				#print fileD
def unpack(filename):
	with open(filename, 'rb') as fp:
		data = fp.read()
		offset = 0
		header = Header()
		header.unpack(data[offset:offset+len(header)])
		if debug:
			print header
			print
		
		assert header.type == 0x00000001, 'Unsupported Type'
		if header.itemCount > 0:
			dataEnc = data[header.dataOff:header.dataOff+header.dataSize]
			context = keyToContext(header.QADigest)
			
			decData = crypt(context, dataEnc, header.dataSize)
			directory = nullterm(header.contentID)
			try:
				os.makedirs(directory)
			except Exception, e:
				pass
			fileDescs = []
			for i in range(0, header.itemCount):
				fileD = FileHeader()
				fileD.unpack(decData[0x20 * i:0x20 * i + 0x20])
				fileD.doWork(decData)
				fileDescs.append(fileD)
				if debug:
					print fileD
				fileD.dump(directory, decData, header)
def getFiles(files, folder):
	foundFiles = glob.glob( os.path.join(folder, '*') )
	sortedList = []
	for filepath in foundFiles:
		if not os.path.isdir(filepath):
			sortedList.append(filepath)
	for filepath in foundFiles:
		if os.path.isdir(filepath):
			sortedList.append(filepath)
	for filepath in sortedList:
		newpath = filepath.replace("\\", "/")
		newpath = "/".join(newpath.split("/")[1:])
		if os.path.isdir(filepath):
			folder = FileHeader()
			folder.fileName = newpath
			folder.fileNameOff 	= 0
			folder.fileNameLength = len(folder.fileName)
			folder.fileOff 		= 0
			
			folder.fileSize 	= 0
			folder.flags		= TYPE_OVERWRITE_ALLOWED | TYPE_DIRECTORY
			folder.padding 		= 0
			files.append(folder)
			getFiles(files, filepath)
		else:
			file = FileHeader()
			file.fileName = newpath
			file.fileNameOff 	= 0
			file.fileNameLength = len(file.fileName)
			file.fileOff 		= 0
			file.fileSize 	= os.path.getsize(filepath)
			file.flags		= TYPE_OVERWRITE_ALLOWED | TYPE_RAW
			if newpath == "USRDIR/EBOOT.BIN":
				file.fileSize = ((file.fileSize - 0x30 + 63) & ~63) + 0x30
				file.flags		= TYPE_OVERWRITE_ALLOWED | TYPE_NPDRMSELF
			
			file.padding 		= 0
			files.append(file)
			
def pack(configfile, folder, outname=None):
	configfp = open(configfile, 'r')
	
	config = ConfigParser.ConfigParser()
	config.readfp(io.BytesIO("[main]\r\n" + configfp.read()))
	configfp.close()
	
	try:
		contentid = config.get('main', "content_id")
		klicensee = config.get('main', "k_licensee").decode('hex')
		contenttype = config.get('main', "contenttype")
	except Exception, e:
		print configfile + " is not valid:\n" + e.message
	qadigest = hashlib.sha1()
	
	header = Header()
	header.magic = 0x7F504B47
	header.type = 0x01
	header.pkgInfoOff = 0xC0
	header.unk1 = 0x05
	
	header.headSize = 0x80
	header.itemCount = 0
	header.packageSize = 0
	
	header.dataOff = 0x140
	header.dataSize = 0
	
	for i in range(0, 0x30):
		header.contentID[i] = 0
	
	for i in range(0,0x10):
		header.QADigest[i] = 0
		header.KLicensee[i] = 0
	for i in range(0, min(0x10, len(klicensee))):
		header.KLicensee[i] = ord(klicensee[i])
	
	
	metaBlock = MetaHeader()
	metaBlock.unk1 		= 1 #doesnt change output of --extract
	metaBlock.unk2 		= 4 #doesnt change output of --extract
	metaBlock.drmType 	= 3 #1 = Network, 2 = Local, 3 = Free, anything else = unknown
	metaBlock.unk4 		= 2 
	
	metaBlock.unk21 	= 4
	metaBlock.unk22 	= 5 #5 == gameexec, 4 == gamedata
	metaBlock.unk23 	= 3
	metaBlock.unk24 	= 4
	
	metaBlock.unk31 	= 0xE   #packageType 0x10 == patch, 0x8 == Demo&Key, 0x0 == Demo&Key (AND UserFiles = NotOverWrite), 0xE == normal, use 0xE for gamexec, and 8 for gamedata
	metaBlock.unk32 	= 4   #when this is 5 secondary version gets used??
	metaBlock.unk33 	= 8   #doesnt change output of --extract
	metaBlock.secondaryVersion 	= 0
	metaBlock.unk34 	= 0
	
	metaBlock.dataSize 	= 0
	metaBlock.unk42 	= 5
	metaBlock.unk43 	= 4
	metaBlock.packagedBy 	= 0x1061
	metaBlock.packageVersion 	= 0
	
	
	files = []
	getFiles(files, folder)
	header.itemCount = len(files)
	dataToEncrypt = ""
	fileDescLength = 0
	fileOff = 0x20 * len(files)
	for file in files:
		alignedSize = (file.fileNameLength + 0x0F) & ~0x0F
		file.fileNameOff = fileOff
		fileOff += alignedSize
	for file in files:
		file.fileOff = fileOff
		fileOff += (file.fileSize + 0x0F) & ~0x0F
		dataToEncrypt += file.pack()
	for file in files:
		alignedSize = (file.fileNameLength + 0x0F) & ~0x0F
		dataToEncrypt += file.fileName
		dataToEncrypt += "\0" * (alignedSize-file.fileNameLength)
	fileDescLength = len(dataToEncrypt)
	for file in files:
		if not file.flags & 0xFF == TYPE_DIRECTORY:
			path = os.path.join(folder, file.fileName)
			fp = open(path, 'rb')
			fileData = fp.read()
			qadigest.update(fileData)
			fileSHA1 = SHA1(fileData)
			fp.close()
			if fileData[0:9] == "SCE\0\0\0\0\x02\x80":
				fselfheader = SelfHeader()
				fselfheader.unpack(fileData[0:len(fselfheader)])
				appheader = AppInfo()
				appheader.unpack(fileData[fselfheader.AppInfo:fselfheader.AppInfo+len(appheader)])
				found = False
				digestOff = fselfheader.digest
				while not found:
					digest = DigestBlock()
					digest.unpack(fileData[digestOff:digestOff+len(digest)])
					if digest.type == 3:
						found = True
					else:
						digestOff += digest.size
					if digest.isNext != 1:
						break
				digestOff += len(digest)
				if appheader.appType == 8 and found:
					dataToEncrypt += fileData[0:digestOff]
					
					meta = EbootMeta()
					meta.magic = 0x4E504400
					meta.unk1 			= 1
					meta.drmType 		= metaBlock.drmType
					meta.unk2			= 1
					for i in range(0,min(len(contentid), 0x30)):
						meta.contentID[i] = ord(contentid[i])
					for i in range(0,0x10):
						meta.fileSHA1[i] 		= ord(fileSHA1[i])
						meta.notSHA1[i] 		= (~meta.fileSHA1[i]) & 0xFF
						if i == 0xF:
							meta.notXORKLSHA1[i] 	= (1 ^ meta.notSHA1[i] ^ 0xAA) & 0xFF
						else:
							meta.notXORKLSHA1[i] 	= (0 ^ meta.notSHA1[i] ^ 0xAA) & 0xFF
						meta.nulls[i] 			= 0
					dataToEncrypt += meta.pack()
					dataToEncrypt += fileData[digestOff + 0x80:]
				else:
					dataToEncrypt += fileData
			else:
				dataToEncrypt += fileData
			
			dataToEncrypt += '\0' * (((file.fileSize + 0x0F) & ~0x0F) - len(fileData))
	header.dataSize = len(dataToEncrypt)
	metaBlock.dataSize 	= header.dataSize
	header.packageSize = header.dataSize + 0x1A0
	head = header.pack()
	qadigest.update(head)
	qadigest.update(dataToEncrypt[0:fileDescLength])
	QA_Digest = qadigest.digest()
	
	for i in range(0, 0x10):
		header.QADigest[i] = ord(QA_Digest[i])
		
	for i in range(0, min(len(contentid), 0x30)):
		header.contentID[i] = ord(contentid[i])
	
	context = keyToContext(header.QADigest)
	setContextNum(context, 0xFFFFFFFFFFFFFFFF)
	licensee = crypt(context, listToString(header.KLicensee), 0x10)
	
	for i in range(0, min(len(contentid), 0x10)):
		header.KLicensee[i] = ord(licensee[i])
	
	if outname != None:
		outFile = open(outname, 'wb')
	else:
		outFile = open(contentid + ".pkg", 'wb')
	outFile.write(header.pack())
	headerSHA = SHA1(header.pack())[3:19]
	outFile.write(headerSHA)
	
	
	metaData = metaBlock.pack()
	metaBlockSHA = SHA1(metaData)[3:19]
	metaBlockSHAPad = '\0' * 0x30
	
	context = keyToContext([ord(c) for c in metaBlockSHA])
	metaBlockSHAPadEnc = crypt(context, metaBlockSHAPad, 0x30)
	
	context = keyToContext([ord(c) for c in headerSHA])
	metaBlockSHAPadEnc2 = crypt(context, metaBlockSHAPadEnc, 0x30)
	outFile.write(metaBlockSHAPadEnc2)
	outFile.write(metaData)
	outFile.write(metaBlockSHA)
	outFile.write(metaBlockSHAPadEnc)
	
	context = keyToContext(header.QADigest)
	encData = crypt(context, dataToEncrypt, header.dataSize)
	outFile.write(encData)
	outFile.write('\0' * 0x60)
	outFile.close()
	print header
	
def usage():
	print """usage: [based on revision 1061]

    python pkg.py config-file target-directory [out-file]

    python pkg.py [options] npdrm-package
        -l | --list             list packaged files.
        -x | --extract          extract package.

    python pkg.py [options]
        --version               print revision.
        --help                  print this message."""

def version():
	print """pky.py 0.5"""

def main():
	global debug
	extract = False
	list = False
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hx:dvl:", ["help", "extract=", "debug","version", "list="])
	except getopt.GetoptError:
		usage()
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("-h", "--help"):
			usage()
			sys.exit(2)
		elif opt in ("-v", "--version"):
			version()
			sys.exit(2)
		elif opt in ("-x", "--extract"):
			fileToExtract = arg
			extract = True
		elif opt in ("-l", "--list"):
			fileToList = arg
			list = True
		elif opt in ("-d", "--debug"):
			debug = True
		else:
			usage()
			sys.exit(2)
	if extract:
		unpack(fileToExtract)
	elif list:
		listPkg(fileToList)
	else:
		if len(args) == 2:
			pack(args[0], args[1])
		elif len(args) == 3:
			pack(args[0], args[1], args[2])
		else:
			usage()
			sys.exit(2)
if __name__ == "__main__":
	main()
