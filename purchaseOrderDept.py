import socket 
import rsa
import sqlite3
import sys
import hashlib
                  
port = 8080 
host = '127.0.0.1' 
size = 4098 
idPurDept = "pur123"
kdc = 'KDC'.encode('utf8')
pubkeyUser = None
hashUser = None
hashSupervisor = None


def main():
	#Reading supervisor's private key
	f = open("prvpurDept.txt", "rb")
	privateKeyPurDept1 = f.read()
	privateKeyPurDept = rsa.PrivateKey.load_pkcs1(privateKeyPurDept1)
	f.close()

	#Reading user's public key
	#Need to replace with CA giving Public key of user along with IP
	'''
	f =  open("pubUser.txt", "rb")
	pubkeyUser1 = f.read()
	pubkeyUser = rsa.PublicKey.load_pkcs1(pubkeyUser1)
	f.close()
	'''
	#Socket creation, binding and listening                    
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)               
	s.bind((host, port))            
	s.listen(15)   
		       
	while True:
		print('purchase department listening....')
		# Establish connection with client.
		conn, addr = s.accept() 
    
		print('Got connection from', addr)
		cipher = conn.recv(size)
		if cipher == kdc:
			print("entered KDC loop")
			sendBytes = conn.send("give the user keys".encode('utf8'))
			recvBytes = conn.recv(size)
			pubkeyUser = rsa.PublicKey.load_pkcs1(recvBytes)
			print("publicKeyUSer: ", pubkeyUser)
			conn.close()
			continue

		if sys.getsizeof(cipher)>0:
			message = rsa.decrypt(cipher, privateKeyPurDept)
			print("from user: ", message)
			message = str(message)
			#find nonce , encrypt another msg in user's public key
			hello, idUser, ipUser, role, nonce = message.split(" ")		
			_, nonce = nonce.split("=")
			_, idUser = idUser.split("=")	
			_, role = role.split('=')
		else:
			print("no data from user")
			exit()

		#Encrytpting in user's public key and sending reply to mutual authentication
		helloMessage = "helloUser" + " id=" + idPurDept + " Nonce=" + nonce
		helloMessage = helloMessage.encode('utf8')
		cipher = rsa.encrypt(helloMessage, pubkeyUser)
		sendbytes = conn.send(cipher)
		if sendbytes > 0:
			print("Sucessdfully sent data to user")
		else:
			print("no data sent to user")
			exit()

		#Waiting to receive order details from user
		orderDetails = conn.recv(size)
		if sys.getsizeof(orderDetails) > 0:
			#decrypting order details
			orderDetailsDecrypt = rsa.decrypt(orderDetails, privateKeyPurDept)
		else:
			print("no order details received from user")

		response = "OK"
		sendbytes = conn.send(response.encode('utf8'))
		print("recieved order details:", orderDetailsDecrypt)
		signature = conn.recv(size)
		if sys.getsizeof(signature) > 0:
			print("recieved signature from user")
			response = "Done"
			sendbytes = conn.send(response.encode('utf8'))
		else:
			print("no signature received from user")

		#Validating signature
		if rsa.verify(orderDetailsDecrypt, signature, pubkeyUser):
			print("signature of user has been verified")
			conn = connectionOpen()
			cur = conn.cursor()
			#Update the status to processing
			orderDetailsDecrypt = str(orderDetailsDecrypt)
			orderNumber, user, status = orderDetailsDecrypt.split(" ")
			_,orderNumber = orderNumber.split("=")
			_,user = user.split("=")
			_,status = status.split("=")
			status = status[0: len(status)-1]
			print("status is ", status)
			if status == "CREATED":
				print("update order status")
				cur.execute("SELECT * FROM orders WHERE username = ? AND order_number = ? ", (user, orderNumber,))
				rows = cur.fetchall()
				status = rows[0][2]
				print("status is: ", status)
				if(status == 'PROCESSING'):
					print("Order has been processed by the supervisor. Purchase Dept waiting for confirmation from supervisor")
				else:
					print("Order status not processing. Please check")
					exit()
			else:
				print("order status is not created")
				print(status)
				exit()
			
		else:
			print("Signature verification failed. Exiting")
			exit()

		if role == 'user':
			hashUser = hashFile(orderDetailsDecrypt)
		elif role == 'supervisor':
			hashSupervisor = hashFile(orderDetailsDecrypt)
			if hashSupervisor == hashUser:
				print("Order Authentication completed: hash values matching")
				cur.execute("UPDATE orders SET status = ?", ("COMPLETED",))
				conn.commit()
				connectionClose(conn)
			else:
				print("hash values mismatching")
				exit()
		else:
			print("role not matching")
			exit()
#Database connection open
def connectionOpen():
	conn = sqlite3.connect('database.db')
	return conn

#Database connection close
def connectionClose(conn):
	conn.close()
	return

def hashFile(orderDetails):
	print("performing hashing")
	hashObject = hashlib.sha3_224()
	#Converting string to a byte objeect
	hashObject.update(orderDetails.encode('utf8'))
	digest = hashObject.digest()
	return digest

main()

