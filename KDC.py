import sqlite3
import rsa
import time
import socket


port = 5055 
host = '127.0.0.1' 
size = 4098 


def main():
	#Socket creation
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)               
	s.bind((host, port))            
	s.listen(15) 

	"reading it's private key"
	f = open("prvKDC.txt", "rb")
	privateKeyKDC1 = f.read()
	privateKeyKDC = rsa.PrivateKey.load_pkcs1(privateKeyKDC1)
	f.close()
	  			      
	while True:
		print('KDC listening....')
		# Establish connection with client.
		sockNew, addr = s.accept()
		#Recieving the public key request from user ad decrypting iy 
		cipher = sockNew.recv(size)
		message = rsa.decrypt(cipher, privateKeyKDC)
		message = str(message)
		idFrom, idTo, ipTo, timestamp, role = message.split(' ')
		_, idFrom = idFrom.split('=')
		_, idTo = idTo.split('=')
		_, ipTo = ipTo.split('=')
		_, role = role.split('=')
		_, timestamp = timestamp.split('=')
		role = role[0:len(role)-1]

		#Verification of timestamp recieved with current time to prevent replay attacks
		timestamp = float(timestamp)
		timestampCurrent = time.time()
		if(timestampCurrent - timestamp) > 120:
			print("Valid time period expired, possible replay attack")
			sockNew.send("Valid time period expired, possible replay attack".encode('utf8'))
			sockNew.close()
			continue

		conn = connectionOpen()
		cur = conn.cursor()
		cur.execute("SELECT * FROM KDCDirectory WHERE IP=? AND ID=? AND Role=?",(ipTo, idTo, role,))
		rows = cur.fetchall()
		print(rows)
		#filepath having the public key of supervisor
		filepath = rows[0][3]
		print(filepath)
		f = open(filepath, "rb")
		key = f.read()	
		f.close()
		send_bytes = sockNew.send(key)
		sockNew.close()
		connectionClose(conn)


#Database connection open
def connectionOpen():
	conn = sqlite3.connect('db1.db')
	return conn

#Database connection close
def connectionClose(conn):
	conn.close()
	return

def sockConnect(ip,port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	return s

main()


