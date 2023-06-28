from pwn import *
import sys

if len(sys.argv) != 2:
	print("Invalid Arguments!")
	print(">> {} <sha265sum>".format(sys.argv[0]))
	exit()

wanted_hash= sys.argv[1]
password_file = "rockyou.txt"
attempts = 0

with log.progress("Attempting To Back: {}!\n".format(wanted_hash)) as p:
  with open(password_file,"r",encoding ='latin-1') as password_list:
  	for password in password_list:
  		password = password.strip("\n").encode('latin-1')
  		password_hash = sha256sumhex(password)
  		p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))
  		if password_hash == wanted_hash:
  			p.success("Password Hash Found After {} Attempts! {} hashes to {}!".format(attempts, password.decode('latin-1'),password_hash))
  			exit()
  			attempts +=1
  			p.failure("Password Hash Not Found!")
