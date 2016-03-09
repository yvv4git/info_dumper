#!/usr/bin/python
# -*- coding: utf-8 -*-
import pefile
import argparse
import os, sys
from datetime import datetime
import sqlite3

# Global vars
file_db = 'result.db'
file_html = 'result.html'


# Foo
def DB_Add(v_datetime, v_filename, v_filetype, v_filepath, v_result, v_crashreport, v_pefiledump):	
	if os.path.isfile(file_db):
		con = sqlite3.connect(file_db)
		cur = con.cursor()
		sql = 'insert into Results(id, dt, fn, ft, fp, rt, cr, pd) values(null, "%s", "%s", "%s", "%s", "%s", "%s", "%s")' % (v_datetime, v_filename, v_filetype, v_filepath, v_result, v_crashreport, v_pefiledump)
		cur.execute(sql)
		con.commit()
	else:
		con = sqlite3.connect(file_db)
		cur = con.cursor()
		cur.execute('create table Results(id integer primary key, dt varchar(20), fn varchar(30), ft varchar(10), fp varchar(256), rt boolean, cr text, pd text )')
		con.commit()
		sql = 'insert into Results(id, dt, fn, ft, fp, rt, cr, pd) values(null, "%s", "%s", "%s", "%s", "%s", "%s", "%s")' % (v_datetime, v_filename, v_filetype, v_filepath, v_result, v_crashreport, v_pefiledump)
		cur.execute(sql)
		con.commit()
	con.close()

def SearchFiles(sdir):
	search_files = []
	for root, dirs, files in os.walk(sdir):
		search_files += [os.path.join(root,name) for name in files]
	return search_files

def PeCheck(file_name):
	pedump = ''
	peerr = ''
	try:
		pe = pefile.PE(file_name, fast_load=True)
		pedump = pe.dump_info()
		print(" >{}:\tdata successful dumping...".format(file_name))
	except pefile.PEFormatError as peerr:
		print(" >{}:\t{}".format(file_name, peerr))
	return pedump, peerr

def H_Header():
	f = open(file_html, 'a')
	f.write('<html>\n')
	f.write('<head>\n')
	f.write('<meta charset="utf-8">\n')
	f.write('<title>\n')
	f.write('Results')
	f.write('</title>\n')
	f.write('</head>\n')
	f.write('<body>\n')
	f.write('<table border="1">')
	f.write('<tr>\n')
	f.write('<th>\n')
	f.write('ID теста')
	f.write('</th>\n')
	f.write('<th>\n')
	f.write('Дата и время')
	f.write('</th>\n')
	f.write('<th>\n')
	f.write('Имя файла')
	f.write('</th>\n')
	f.write('<th>\n')
	f.write('Тип файла')
	f.write('</th>\n')
	f.write('<th>\n')
	f.write('Путь к файлу')
	f.write('</th>\n')
	f.write('<th>\n')
	f.write('Результат теста')
	f.write('</th>\n')
	f.write('<th>\n')
	f.write('Crash report')
	f.write('</th>\n')
	f.write('</tr>\n')
	f.close()

def H_Footer():
	f = open(file_html, 'a')
	f.write('</table>')
	f.write('</body>\n')
	f.write('</html>\n')
	f.close()


def H_Add(v_id, v_datetime, v_filename, v_filetype, v_filepath, v_result, v_crash):
	f = open(file_html, 'a')
	f.write('<tr>')
	f.write('<td>\n')
	f.write(str(v_id))
	f.write('</td>\n')
	f.write('<td>\n')
	f.write(v_datetime)
	f.write('</td>\n')
	f.write('<td>\n')
	f.write(v_filename)
	f.write('</td>\n')
	f.write('<td>\n')
	f.write(v_filetype)
	f.write('</td>\n')
	f.write('<td>\n')
	f.write(v_filepath)
	f.write('</td>\n')
	f.write('<td>\n')
	f.write(v_result)
	f.write('</td>\n')
	f.write('<td>\n')
	f.write(v_crash)
	f.write('</td>\n')	
	f.write('</tr>\n')
	f.close()


def DB_Get():
	if os.path.isfile(file_db):
		con = sqlite3.connect(file_db)
		cur = con.cursor()
		sql = 'select * from Results'
		cur.execute(sql)
		listOfRes = cur.fetchall()
		con.commit()
		con.close()
		return listOfRes
	else:
		print("[-] Don't find data-base")
		return null

def H_CreateResult():
	if not os.path.isfile(file_html):
		H_Header()
		listOfRes = DB_Get()
		for r in listOfRes:
			H_Add(r[0], r[1], r[2], r[3], r[4], r[5], r[6])
		H_Footer()
	else:
		os.remove(file_html)

def Main():
	parser = argparse.ArgumentParser(description='Special test programm.')
	parser.add_argument('dirorfile')
	args = parser.parse_args()
	
	d = datetime.now()
	date_and_time = datetime.strftime(d, "%Y.%m.%d %H:%M:%S")
	

	arr_f = []
	if (str(args.dirorfile) != 'None'):
		print "[*] Directory:", args.dirorfile
		if (os.path.isdir(str(args.dirorfile))):
			print("[*] {} directory exists".format(str(args.dirorfile)))
			arr_f = SearchFiles(str(args.dirorfile))
			print("[*] Count of files:\t{}".format(len(arr_f)))
			for f in arr_f:
				pdump, perr = PeCheck(f)
				if pdump != '':
					DB_Add(date_and_time, os.path.basename(f), 'PE-file', os.path.abspath(f), 'true', perr, pdump)
				else:
					DB_Add(date_and_time, os.path.basename(f), 'Not PE', os.path.abspath(f), 'false', perr, pdump)
			H_CreateResult()
		elif (os.path.exists(str(args.dirorfile))):
			print("[*] {} file exists".format(str(args.dirorfile)))
			pdump, perr = PeCheck(str(args.dirorfile))
			if pdump != '':
				DB_Add(date_and_time, os.path.basename(str(args.dirorfile)), 'PE-file', os.path.abspath(str(args.dirorfile)), 'true', perr, pdump)
			else:
				DB_Add(date_and_time, os.path.basename(str(args.dirorfile)), 'Not PE', os.path.abspath(str(args.dirorfile)), 'false', perr, pdump)			
			H_CreateResult()
		else:
			print "[-] This is bad path or file"

if __name__ == "__main__":
	Main()
