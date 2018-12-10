import socket 
import rsa
import sqlite3
import sys
import random
                  
port = 9090 
host = '127.0.0.1' 
size = 4098 
idSupervisor = "sup123"
ipSupervisor = '127.0.0.1:9090'
purDeptid = 'pur123'
purDeptip = '127.0.0.1:8080'
pubkeyUser = None
counter = 0
kdc = 'KDC'.encode('utf8')

#reading public key of KDC
f = open("pubKDC.txt", "rb")
pubkeyKDC1 = f.read()
pubkeyKDC = rsa.PublicKey.load_pkcs1(pubkeyKDC1)
f.close()


def main():
	#Reading supervisor's private key
	f = open("pvtsup.txt", "rb")
	privateKeySupervisor1 = f.read()
	privateKeySupervisor = rsa.PrivateKey.load_pkcs1(privateKeySupervisor1)
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
		print('Supervisor listening....')
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
			message = rsa.decrypt(cipher, privateKeySupervisor)
			print("from user: ", message)
			message = str(message)
			#find nonce , encrypt another msg in user's public key
			hello, idUser, ipUser, nonce = message.split(" ")		
			_, nonce = nonce.split("=")
			_, idUser = idUser.split("=")
		else:
			print("no data from user")
			exit()

		#Encrytpting in user's public key and sending reply to mutual authentication
		helloMessage = "helloUser" + " id=" + idSupervisor + " Nonce=" + nonce
		helloMessage = helloMessage.encode('utf8')
		cipher = rsa.encrypt(helloMessage, pubkeyUser)
		sendbytes = conn.send(cipher)
		#Waiting to receive order details from user
		orderDetails = conn.recv(size)
		#decrypting order details
		if sys.getsizeof(orderDetails) > 0:
			#decrypting order details
			orderDetailsDecrypt = rsa.decrypt(orderDetails, privateKeySupervisor)
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
			orderDetailsDecrypt = orderDetailsDecrypt.decode('utf8')
			orderNumber, user, status = orderDetailsDecrypt.split(" ")
			_,orderNumber = orderNumber.split("=")
			_,user = user.split("=")
			_,status = status.split("=")
			if status == "CREATED":
				print("update order status")
				cur.execute("UPDATE orders SET status = ? WHERE username = ? AND order_number = ? ", ("PROCESSING", user, orderNumber ))
				conn.commit()
				connectionClose(conn)
			else:
				print("order status is not created")
				print(status)
				exit()
			
		else:
			print("Signature verification failed. Exiting")
			exit()

		#sending data to purchase department
		contactPurchaseDept(orderDetailsDecrypt,privateKeySupervisor)
		

#Database connection open
def connectionOpen():
	conn = sqlite3.connect('database.db')
	return conn

#Database connection close
def connectionClose(conn):
	conn.close()
	return

def contactPurchaseDept(orderDetails, privateKeySupervisor):
		#Requesting for purchase department's public key from KDC
		#siganture
		signaturesupervisor = rsa.sign(orderDetails.encode('utf8'), privateKeySupervisor, 'SHA-224')

		requestMsg = "idfrom=" + 'sup123' + " idTo="  + purDeptid + " ipTo=" + purDeptip + " role=" + "purdept"
		requestMsg = requestMsg.encode('utf8')
		requestMsgCipher = encrypt_RSA(requestMsg, pubkeyKDC)
		sock = KDCConnect()
		datasent = sock.send(requestMsgCipher)
		if datasent > 0:
			print("request message sent sucessfully to the KDC")
		else:
			print("Some error occured while sending data to KDC. Exiting")
			exit()

		datarecv = sock.recv(size)
		pubKeyPurDept = rsa.PublicKey.load_pkcs1(datarecv)
		if sys.getsizeof(datarecv) > 0:
			print("public key recieved sucessfully from KDC")
		else:
			print("error in receiving public key")
			exit()
		sock.close()
	
		#sending order to purchase department 
		#Mutual Authentication with purchase department. Need to pass hello msg + pubkey of purchaseDept + ID of user + IP address of User + Nonce
		noncePurDeptsent = random.randint(10,500)
		ipUser = "127.0.0.1:5000"
		print("Creating hello message for purchase department")
		message = "hello" + " id=" + 'sup123' + " ipaddress=" + ipSupervisor + " role=" + 'supervisor' + " Nonce=" + str(noncePurDeptsent)
		print(message)
		print("converting message to bytes")
		message = message.encode('utf8')
		print(message)	
		hellopurDept = encrypt_RSA(message, pubKeyPurDept)
		
		#connect to purchase department
		socketDesc = purDeptConnect()

		#send the authentication message to supervisor
		receivedData = sendOrderToPurDept(socketDesc, hellopurDept)
		print("decrypting response from purchas depr")
		pureptHello = decrypt_RSA(receivedData, privateKeySupervisor)
		pureptHello = str(pureptHello)
		print("purchase dept hello response ", pureptHello)
		#validating the nonce sent and recvd
		_, _, noncePurDeptRecvd = pureptHello.split(" ")
		_, noncePurDeptRecvd = noncePurDeptRecvd.split("=")
		noncePurDeptRecvd = noncePurDeptRecvd[0: len(noncePurDeptRecvd) -2]

		if str(noncePurDeptsent) == noncePurDeptRecvd:
			print("Nonce recieved from purchase department is matching with the nonce sent ")
			#encrypting the file using supervisor's public key
			order = orderDetails.encode('utf8')
			print("encrypting order and signature")
			cipherPurDept = encrypt_RSA(order, pubKeyPurDept)
			r = sendOrderToPurDept(socketDesc, cipherPurDept)
			print(r)
			print("recieved response from purchase dept after order")
			r = sendOrderToPurDept(socketDesc, signaturesupervisor)
			print(r)
			socketDesc.close()
		else:
			print("Nonce sent and recvd from purchase dept not matching")
			socketDesc.close()
			exit()
		return

#Encrypting file using RSA
def encrypt_RSA(message, public_key):
	cipher = rsa.encrypt(message, public_key)
	return cipher

#Decryption using RSA
def decrypt_RSA(cipher_text, private_key):
	message = rsa.decrypt(cipher_text, private_key)
	return message

def KDCConnect():
	KDCIp = '127.0.0.1'
	KDCPort = 5055
	size = 4098

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((KDCIp, KDCPort))
	return s

def purDeptConnect():
	purDeptIp = '127.0.0.1'
	putDeptPort = 8080
	size = 4098

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((purDeptIp, putDeptPort))
	return s


def sendOrderToPurDept(sock, message):
	sendMsg = sock.send(message)
	if sys.getsizeof(sendMsg)>0:
		print("data sucessfully sent to purchase dept")
	else:
		print("data was not sent to purchase dept")
		exit()

	msgFromPurDept = sock.recv(size)
	if sys.getsizeof(msgFromPurDept)>0:
		print("data sucessfully received from purchase dept")
	else:
		print("data was not received from purchase dept")
		exit()
	print("response from purchase dept: ", str(msgFromPurDept)) 
	return msgFromPurDept

main()

