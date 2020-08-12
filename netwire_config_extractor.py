#!/usr/bin/python2

import re
import sys
import struct
from collections import OrderedDict

def readIntBin(pe_data, coffset, doffset):
	return struct.unpack("<I", pe_data[coffset + doffset: coffset + doffset + 0x4])[0]

def get_image_base(pe_data):
	optional_header_offset = struct.unpack("<I", pe_data[0x3C : 0x3C + 4])[0]
	return readIntBin(pe_data, optional_header_offset, 0x34)
	
def config_search(pe_data):
	conf_pat = re.search(re.compile("\x8D(...)\xC7\x44(......)\xC7\x44(......)\x89(..)\xE8(..)\x00\x00\x89(..)\xC7\x44(.)\x08\xFF\x00\x00\x00"), pe_data)
	if conf_pat:  
		return conf_pat.start()
	else:
		return 0
	
def conf_keygen(pe_data, coffset):
	key_size = readIntBin(pe_data, coffset, 0x8)
	key_off = readIntBin(pe_data, coffset, 0x10) - get_image_base(pe_data)
	
	arry = []
	for x in range(0x0, 0x100):
		arry.append(x)	
		
	var00 = 0
	var01 = 0
	for x in range(0, 0x100):
		var02 = arry[x]
		var01 = (var02 + bytearray(pe_data[key_off: key_off + key_size])[var00] + var01) & 0x000000FF
		arry[x] = arry[var01]
		arry[var01] = var02
		var00 = (var00 + 1) % key_size
	return arry

def dec_conf(pe_data, data_size, data_off, genkey):
	enc_data = bytearray(pe_data[data_off: data_off + data_size])
	dec_data = []
	
	var00 = 0
	var01 = 0
	for x in range(0x00, data_size):
		var02 = genkey[x+1]
		var00 = (var00 + var02) & 0x000000FF
		var01 = genkey[var00]
		genkey[x+1] = var01
		genkey[var00] = var02
		dec_data.append(enc_data[x] ^ genkey[(var01 + var02) & 0x000000FF])

	attr = ""
	i = 0
	while dec_data[i] != 0x00:
		attr += chr(dec_data[i])
		i += 1
		if i == len(dec_data):
			break
	return attr

def get_conf(pe_data, coffset):
	
	conf_data = OrderedDict()
	conf_attr = ["C2 address", "Unknown00", "AES key", "Host ID", "Group", "Mutex", "Startup", "UUID", "Keylog Dir", "Flag 00", "Flag 01", "Flag 02"]
	for x in range(0, 12):
		data_size = readIntBin(pe_data, coffset, 0x23 + x * 0x18)
		data_off = readIntBin(pe_data, coffset, 0x2B + x * 0x18) - get_image_base(pe_data)
		conf_data[conf_attr[x]] = dec_conf(pe_data, data_size, data_off, conf_keygen(pe_data, coffset))	
	return conf_data

def main():
	if len(sys.argv) < 2:
		print("Usage: netwire_config_extractor.py <netwire sample>")
		exit()	
	pe_file = open(sys.argv[1], "rb")
	pe_data = pe_file.read()
	pe_file.close()
	coffset = config_search(pe_data)
	if coffset:
		conf_data = get_conf(pe_data, coffset)
		for key, values in conf_data.items():
			print("%s:    \t%s") % (key, values)
	else:
		print("Config not found")
	
if __name__== "__main__" :
	main()	

	
	
