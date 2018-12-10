from flask import Flask
from flask import render_template
from flask import request
import sqlite3
from flask import abort
import random
import sys
from flask import session
import socket
import hashlib
import rsa
import sys
import time


app = Flask(__name__)
app.secret_key = '123'
size = 4098
supervisorId = 'vidya'
supervisorIp = '127.0.0.1:9090'
purDeptid = 'rachu'
purDeptip = '127.0.0.1:8080'

#reading public key of supervior
#need to replace it with CA sending

#reading private key of user
f = open("prvUser.txt", "rb")
privateKeyUser1 = f.read()
privateKeyUser = rsa.PrivateKey.load_pkcs1(privateKeyUser1)
f.close()

#reading public key of KDC
f = open("pubKDC.txt", "rb")
pubkeyKDC1 = f.read()
pubkeyKDC = rsa.PublicKey.load_pkcs1(pubkeyKDC1)
f.close()

#Login page
@app.route('/')
def hello_world():
	return render_template('login.html')

#Validation of the user
@app.route('/page', methods = ['POST', 'GET'])
def role():
	if request.method == 'POST':
		session['user'] = request.form['username']
		pwd = request.form['password']
	print("user name = ", session['user']) 
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM users WHERE username=? AND password=?",(session['user'],pwd,))
	rows = cur.fetchall()
	if rows == []:
		abort(500, 'Invalid login credentials')
	role  = rows[0][2]
	print(role)	
	#displaying web pages based on roles
	if role == 'user':
		return render_template('page.html',msg="Welcome "+ session['user'])
	elif role == 'supervisor':
		cur.execute("SELECT * FROM supervisor WHERE orderstatus=?",('CREATED',))
		rows = cur.fetchall()
		return render_template('supervisor.html', rows = rows)
	elif role == 'purchase':
		cur.execute("SELECT * FROM orders WHERE status=?",('PROCESSING',))
		rows = cur.fetchall()
		return render_template('purchase.html', rows=rows)
	connectionClose(conn)

#Displaying Order Creation Page
@app.route('/orderCreate')
def orderCreation():
	return  render_template('orderCreate.html',user=session['user'])

@app.route('/result', methods = ["POST"])
def result():
	#Opening the data base connections
	conn = connectionOpen()
	cur = conn.cursor()
	print("user name result= ", session['user'])
	numberOfItems = request.form['numberofitems']
	creditcardNumber = request.form['creditcard']
	ordernumber = random.randint(1,10000)
	session['orderNumber'] = str(ordernumber)
	cur.execute("INSERT INTO orders (order_number, username, status, numberofitems, creditcard, ipAddress) VALUES (?, ?, ?,?,?,?)", (ordernumber, session['user'], "CREATED", 				   		int(numberOfItems),creditcardNumber,"127.0.0.1:5000"))
	conn.commit()
	msg = 'Order number: ' + str(ordernumber) + ' is created sucessfully'
	return  render_template('requestKeys.html',msg = msg)

@app.route('/requestKeys', methods = ["POST"])
def reQuestKeys():
	sock = KDCConnect()
	#Requesting Supervisor Key
	requestSupervisor = "idfrom=" + session['user'] + " idTo="  + supervisorId + " ipTo=" + supervisorIp + " timestamp="+ str(time.time()) + " role=" + "supervisor"
	requestSupervisor = requestSupervisor.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestSupervisor, pubkeyKDC)
	datasent = sock.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for supervisor public key to Central Authority. Exiting"
		abort(500, msg)

	datarecv = sock.recv(size)
	session['pubKeySuper'] = datarecv
	if sys.getsizeof(datarecv) > 0:
		print("public key recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of supervisor")
		abort(500,"error in receiving public key of supervisor")
		
	sock.close()
	
	#Requesting purchase department's key
	print("request purchase dept's public key")
	sock1 = KDCConnect()
	requestPurchase = "idfrom=" + session['user'] + " idTo="  + purDeptid + " ipTo=" + purDeptip + " timestamp="+ str(time.time()) + " role=" + "purdept"
	requestPurchase = requestPurchase.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestPurchase, pubkeyKDC)
	datasent = sock1.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for purchase dept: public key to Central Authority. Exiting"
		abort(500, msg)

	datarecv = sock1.recv(size)
	session['pubKeyPurchase'] = datarecv

	if sys.getsizeof(datarecv) > 0:
		print("public key of purchase department recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of purchase department")
		abort(500,"error in receiving public key of purchase department")
		sock1.close()
		
	sock1.close()
	msg = "Supervisor's public key and purchase department's public key has been sucessfully received from the central authority"
	return  render_template('sendOrder.html',msg = msg)

@app.route('/sendOrder', methods = ["POST"])
def sendOrder():
	conn = connectionOpen()
	cur = conn.cursor()
	orderDetails = "order=" + session['orderNumber']  + " user=" + session['user'] + " status=" + "CREATED"
	pubKeySupervisor = rsa.PublicKey.load_pkcs1(session['pubKeySuper'])
	pubKeyPurchase = rsa.PublicKey.load_pkcs1(session['pubKeyPurchase'])

	orderDetailsEncryptSupervisor = rsa.encrypt(orderDetails.encode('utf8'),pubKeySupervisor)
	orderDetailsEncryptpurchase = rsa.encrypt(orderDetails.encode('utf8'),pubKeyPurchase)
	signatureUser = rsa.sign(orderDetails.encode('utf8'), privateKeyUser, 'SHA-224')
	print(orderDetailsEncryptSupervisor)


	cur.execute("UPDATE orders SET signature_client = ? WHERE order_number=?", (str(signatureUser),session['orderNumber']))
	conn.commit()

	#cur.execute("INSERT INTO supervisor (order, encryptedData, signatureUser) VALUES (?,?,?)", ("order1", orderDetailsEncryptSupervisor, signatureUser))
	orderLabel = session['orderNumber']
	cur.execute("INSERT INTO supervisor (orderLabel,encryptedData,signatureUser,orderstatus) VALUES (?, ?, ?,?)", (orderLabel, orderDetailsEncryptSupervisor, signatureUser,"CREATED"))
	cur.execute("INSERT INTO purchasedepartment (orderLabel,encryptedData,signatureUser,orderstatus) VALUES (?,?,?,?)", (orderLabel, orderDetailsEncryptpurchase,signatureUser,"CREATED"))
	conn.commit()
	
	msg = "order details and signature sucessfully sent to supervisor and purchase department"
	return  render_template('orderEnd.html',msg = msg)

	
@app.route('/supervisorApproval', methods = ["POST"])
def supervisorApproval():
	orderNumber = request.form['order']
	session["orderNumberSuper"] = orderNumber
	print("order number is ", orderNumber)
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM supervisor WHERE orderLabel=?",(orderNumber,))
	rows = cur.fetchall()
		
	encryptedData = rows[0][1]
	signatureUser = rows[0][2]
	
	privateKeySupervisor = pvtKeySup()

	decryptedData = rsa.decrypt(encryptedData, privateKeySupervisor)
	decryptedDatastr = decryptedData.decode('utf8')
	session['decrypteddOrderSuper'] = decryptedData
	order, user, status = decryptedDatastr.split(' ')
	_,order = order.split('=')
	_,user = user.split('=')
	_,status = status.split('=')

	cur.execute("SELECT * FROM orders WHERE order_number=?",(order,))
	rowsOrder = cur.fetchall()
	ipAddressUser = rowsOrder[0][6]

	#request for user's public key
	sock = KDCConnect()
	requestUser = "idfrom=" + session['user'] + " idTo="  + user + " ipTo=" + ipAddressUser + " timestamp="+ str(time.time()) + " role=" + "user"
	requestUser = requestUser.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestUser, pubkeyKDC)
	print(requestMsgCipher)
	datasent = sock.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for user's public key to Central Authority. Exiting"
		abort(500, msg)

	datarecv = sock.recv(size)
	pubKeyUser = rsa.PublicKey.load_pkcs1(datarecv)
	
	if sys.getsizeof(datarecv) > 0:
		print("public key recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of supervisor")
		abort(500,"error in receiving public key of user")
		
	sock.close()

	#signature verification
	if rsa.verify(decryptedData, signatureUser, pubKeyUser):
		signMsg = "signature verification of user done sucessfully"
		cur.execute("UPDATE supervisor SET orderstatus = ? where orderLabel=?", ("PROCESSING",order))
		conn.commit()
		
		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("PROCESSING",order))
		orderStatusmsg = "PROCESSING"
		conn.commit()
		return render_template('keyPurchaseDept.html',signMsg = signMsg, orderStatusmsg=orderStatusmsg)
		
	else:
		signMsg = "signature verification has failed. Order is rejected automatically"
		orderStatusmsg = "REJECTED"
		cur.execute("UPDATE supervisor SET orderstatus = ? where orderLabel=?", ("REJECTED",order))
		conn.commit()
		cur.execute("SELECT * FROM orders WHERE order_number=?",(orderNumber,))
		rows = cur.fetchall()

		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("REJECTED",order))
		conn.commit()
		abort(404, "Order Rejected due to signature verification failure")


@app.route('/PurchaseDeptKey', methods=["POST"])
def purchaseDeptKey():
	print("request purchase dept's public key")
	sock1 = KDCConnect()
	requestPurchase = "idfrom=" + session['user'] + " idTo="  + purDeptid + " ipTo=" + purDeptip + " timestamp="+ str(time.time()) + " role=" + "purdept"
	requestPurchase = requestPurchase.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestPurchase, pubkeyKDC)
	datasent = sock1.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for purchase dept: public key to Central Authority. Exiting"
		abort(500, msg)

	datarecv = sock1.recv(size)
	session['pubKeyPurchase'] = datarecv

	if sys.getsizeof(datarecv) > 0:
		print("public key of purchase department recieved sucessfully from Central Authority")
		return render_template("sendOrderFromSupToPur.html", msg = "Public Key sucessfully received from Central Authority. Send order to purchase dept")
	else:
		print("error in receiving public key of purchase department")
		abort(500,"error in receiving public key of purchase department")
		sock1.close()	

@app.route('/PurchaseDeptSend', methods=["POST"])
def sendOrderToPurchaseFromoSupervisor():
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM supervisor WHERE orderLabel=?",(session["orderNumberSuper"],))
	rows = cur.fetchall()
	encryptedOrder = rows[0][1]
	pubKeyPurchase = rsa.PublicKey.load_pkcs1(session['pubKeyPurchase'])
	encryptOrderToPurchase = rsa.encrypt(session['decrypteddOrderSuper'],pubKeyPurchase)
	
	#reading pvt key
	privateKeySupervisor = pvtKeySup()
	#signature of supervisor
	signatureSupervisor = rsa.sign(session['decrypteddOrderSuper'], privateKeySupervisor, 'SHA-224')

	#write in purchase departments table
	cur.execute("UPDATE purchasedepartment SET signatureSuper=?, encryptedDataSuper=? WHERE orderLabel=?", (signatureSupervisor, encryptOrderToPurchase,session['orderNumberSuper']))
	conn.commit()
	
	return render_template("supervisorend.html", msg= "Order sucessfully send to purchase department")

@app.route('/purchaseVerify', methods=['POST'])
def purchaseVerify():
	session['orderNumPurchase'] = request.form['order']
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM purchasedepartment WHERE orderLabel=?",(session["orderNumPurchase"],))
	rows = cur.fetchall()
	encryptedDataUser = rows[0][1]
	session['signatureUser'] = rows[0][2]
	session['signatureSuper'] = rows[0][3]
	encryptedDataSuper = rows[0][5]
	
	#Requesting user's public key
	privateKeyPurDept = pvtKeyPur()
	session['decryptDataUser'] = rsa.decrypt(encryptedDataUser, privateKeyPurDept)
	session['decryptDataSupervisor'] = rsa.decrypt(encryptedDataSuper, privateKeyPurDept)

	return render_template('purchaseOrderVerify.html')

@app.route('/purchasehashVerify', methods=["POST"])
def orderhashVerfiy():
	hashUser = hashFile(session['decryptDataUser'].decode('utf8'))
	hashSuper = hashFile(session['decryptDataSupervisor'].decode('utf8'))

	if hashUser == hashSuper:
		msg = "Hash Values Matching"
		return render_template("signatureVerify.html", msg=msg)
	else:	
		msg = "Hash Value Not MAtch. Rejecting the order"
		conn = connectionOpen()
		cur = conn.cursor()
		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("REJECTED",session['orderNumPurchase']))
		cur.execute("UPDATE purchasedepartment SET orderstatus = ? WHERE order_number=?", ("REJECTED",session['orderNumPurchase']))
		abort(500, msg)

@app.route('/signaturehVerify', methods=['POST'])
def signatureVerification():
	#requesting keys for user and supervisor
	order, user, status = session['decryptDataUser'].decode('utf8').split(' ')
	_,order = order.split('=')
	_,user = user.split('=')
	_,status = status.split('=')
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM orders WHERE order_number=?",(order,))
	rowsOrder = cur.fetchall()
	ipAddressUser = rowsOrder[0][6]

	#request for user's public key
	sock = KDCConnect()
	requestUser = "idfrom=" + session['user'] + " idTo="  + user + " ipTo=" + ipAddressUser + " timestamp="+ str(time.time()) + " role=" + "user"
	requestUser = requestUser.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestUser, pubkeyKDC)
	print(requestMsgCipher)
	datasent = sock.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for user's public key to Central Authority. Exiting"
		abort(500, msg)

	datarecv = sock.recv(size)
	pubKeyUser = rsa.PublicKey.load_pkcs1(datarecv)
	
	if sys.getsizeof(datarecv) > 0:
		print("public key recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of supervisor")
		abort(500,"error in receiving public key of user")
		
	sock.close()
	
	verifyUser = rsa.verify(session['decryptDataUser'], session['signatureUser'], pubKeyUser)
	print("Verification User " , verifyUser)


	#Requesting Supervisor Key
	sock = KDCConnect()
	requestSupervisor = "idfrom=" + session['user'] + " idTo="  + supervisorId + " ipTo=" + supervisorIp + " timestamp="+ str(time.time()) + " role=" + "supervisor"
	requestSupervisor = requestSupervisor.encode('utf8')
	requestMsgCipher = encrypt_RSA(requestSupervisor, pubkeyKDC)
	datasent = sock.send(requestMsgCipher)

	if datasent > 0:
		print("request message sent sucessfully to the Central Authority")
	else:
		print("Some error occured while sending data to Central Authority. Exiting")
		msg = "Error occured while sending request for supervisor public key to Central Authority. Exiting"
		abort(500, msg)

	datarecv = sock.recv(size)
	pubKeySuper = rsa.PublicKey.load_pkcs1(datarecv)
	if sys.getsizeof(datarecv) > 0:
		print("public key recieved sucessfully from Central Authority")
	else:
		print("error in receiving public key of supervisor")
		abort(500,"error in receiving public key of supervisor")
		
	sock.close()

	verifySuper = rsa.verify(session['decryptDataSupervisor'], session['signatureSuper'], pubKeySuper)
	print("Verification Super " , verifySuper)
	
	if verifySuper == 'SHA-224' and verifyUser == 'SHA-224':
		msg = "Sucessfully verified signatures"
		cur.execute("UPDATE purchasedepartment SET orderstatus = ? where orderLabel=?", ("APPROVED",order))
		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("APPROVED",order))
		conn.commit()
		return render_template("purchaseend.html", msg= msg, approved = "APPROVED")
	else:	
		if verifySuper != "SHA-224":
			msg = "Supervisor Signature Verification Failed"
		else:
			msg = "User Signature Verification Failed"
		cur.execute("UPDATE purchasedepartment SET orderstatus = ? where orderLabel=?", ("REJECTED",order))
		cur.execute("UPDATE orders SET status = ? WHERE order_number=?", ("REJECTED",order))
		conn.commit()
		abort(500,msg)

def pvtKeySup():
	f = open("pvtsup.txt", "rb")
	privateKeySupervisor1 = f.read()
	privateKeySupervisor = rsa.PrivateKey.load_pkcs1(privateKeySupervisor1)
	f.close()	
	return	privateKeySupervisor

def pvtKeyPur():
	f = open("prvpurDept.txt", "rb")
	privateKeyPurDept1 = f.read()
	privateKeyPurDept = rsa.PrivateKey.load_pkcs1(privateKeyPurDept1)
	f.close()
	return privateKeyPurDept
'''
#Displaying if the order is created sucessfully or not
@app.route('/result', methods = ["POST"])
def result():
	print("user name result= ", session['user'])
	numberOfItems = request.form['numberofitems']
	creditcardNumber = request.form['creditcard']
	#Number of items should be greater than zero
	conn = connectionOpen()
	cur = conn.cursor()
	if numberOfItems.isdigit():

		#Inserting to Database
		print("number of items is integers", file = sys.stdout)
		ordernumber = random.randint(1,10000)
		cur.execute("INSERT INTO orders (order_number, username, status, numberofitems, creditcard) VALUES (?, ?, ?,?,?)", (ordernumber, session['user'], "CREATED", 					int(numberOfItems),creditcardNumber))
		conn.commit()

		#Writing to file
		file_name = "order " + str(ordernumber) + ".txt"
		f = open(file_name, "w+")
		f.write("username: " + session['user'] + '\n')
		f.write(" ordernumber: " + str(ordernumber) + '\n')
		f.write(" status: " + "CREATED" + '\n')
		f.write(" Number of items: " + numberOfItems + '\n')
		f.write(" Credit card number: " + creditcardNumber + '\n')

		orderDetails = "order=" + str(ordernumber) + " user=" + session['user'] + " status=" + "CREATED"

		#Digital Signature of the user
		print("Signature using prvt key of user")
		signatureUser = rsa.sign(orderDetails.encode('utf8'), privateKeyUser, 'SHA-224')

		#signatureUser = encrypt_RSA(digest, privateKeyUser)
		f.write("Signature: " + str(signatureUser))
		f.close()
		
		print("updating in table")
		cur.execute("UPDATE orders SET signature_client = ?", (str(signatureUser),))
		conn.commit()

		#Sending request to KDC for supervisor's key
		requestMsg = "idfrom=" + session['user'] + " idTo="  + supervisorId + " ipTo=" + supervisorIp + " role=" + "supervisor"
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
		pubKeySupervisor = rsa.PublicKey.load_pkcs1(datarecv)
		if sys.getsizeof(datarecv) > 0:
			print("public key recieved sucessfully from KDC")
		else:
			print("error in receiving public key")
			exit()
		time.sleep(5)

		#Mutual Authentication with supervisor. Need to pass hello msg + pubkey of supervisor + ID of user + IP address of User + Nonce
		nonceSupervisorsent = random.randint(10,500)
		ipUser = "198.71.50.07"
		print("Creating hello message for supervisor")
		message = "hello" + " id=" + session['user'] + " ipaddress=" + ipUser + " Nonce=" + str(nonceSupervisorsent)
		print(message)
		print("converting message to bytes")
		message = message.encode('utf8')
		print(message)	
		helloSupervisor = encrypt_RSA(message, pubKeySupervisor)
		
		#connect to supervisor
		socketDesc = supervisorConnect()

		#send the authentication message to supervisor
		receivedData = sendOrderToSupervisor(socketDesc, helloSupervisor)
		print("decrypting response from supervisor")
		supervisorhello = decrypt_RSA(receivedData, privateKeyUser)
		supervisorhello = str(supervisorhello)
		print("supervisor hello response ", supervisorhello)
		#validating the nonce sent and recvd
		_, _, nonceSupervisorRecvd = supervisorhello.split(" ")
		_, nonceSupervisorRecvd = nonceSupervisorRecvd.split("=")
		nonceSupervisorRecvd = nonceSupervisorRecvd[0: len(nonceSupervisorRecvd)-2]
		print("recvd " , nonceSupervisorRecvd)
		print("sent ",nonceSupervisorsent)
		if str(nonceSupervisorsent) == nonceSupervisorRecvd:
			print("Nonce recieved from supervbisor is matching with the nonce sent ")
			#encrypting the file using supervisor's public key
			order = orderDetails.encode('utf8')
			print("encrypting order and signature")
			cipher_supervisor = encrypt_RSA(order, pubKeySupervisor)
			r = sendOrderToSupervisor(socketDesc, cipher_supervisor)
			print(r)
			print("recieved response from supervisor after order")
			r = sendOrderToSupervisor(socketDesc, signatureUser)
			print(r)
			socketDesc.close()
		else:
			print("Nonce sent and recvd from supervisor not matching")
			exit()


		#Requesting for purchase department's public key from KDC
		requestMsg = "idfrom=" + session['user'] + " idTo="  + purDeptid + " ipTo=" + purDeptip + " role=" + "purdept"
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
		message = "hello" + " id=" + session['user'] + " ipaddress=" + ipUser + " role=" + 'user' + " Nonce=" + str(noncePurDeptsent)
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
		pureptHello = decrypt_RSA(receivedData, privateKeyUser)
		pureptHello = str(pureptHello)
		print("purchase dept hello response ", supervisorhello)
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
			r = sendOrderToPurDept(socketDesc, signatureUser)
			print(r)
			socketDesc.close()
		else:
			print("Nonce sent and recvd from purchase dept not matching")
			socketDesc.close()
			exit()


	else:
		connectionClose(conn)
		abort(400)
	time.sleep(5)
	cur.execute("SELECT * FROM orders WHERE username=? AND order_number=?",(session['user'],ordernumber,))
	rows = cur.fetchall()
	connectionClose(conn)
	return  render_template('result.html',rows=rows)
'''

#View Order Status for the user
@app.route('/viewOrderStatus')
def viewOrderStatus():
	print("view status function")
	conn = connectionOpen()
	cur = conn.cursor()
	cur.execute("SELECT * FROM orders where username=?", (session['user'],))
	rows = cur.fetchall() 
	connectionClose(conn)
	return  render_template('viewOrderStatus.html',user=session['user'], rows= rows)

#Database connection open
def connectionOpen():
	conn = sqlite3.connect('database.db')
	return conn

#Database connection close
def connectionClose(conn):
	conn.close()
	return

#Sending order details to the supervisor by user
def sendOrderToSupervisor(sock, message):
	'''
	print("sending data to supervisor")
	print(str(message))
	if str(message).find(".txt", 0 , len(str(message))):
		f.open(str(message), "rb")
		bytes = f.read(size)
		while(bytes):
			sock.send(bytes)
	else:
		sock.send(message)
	'''
	sendMsg = sock.send(message)
	if sys.getsizeof(sendMsg)>0:
		print("data sucessfully sent to supervisor")
	else:
		print("data was not sent to supervisor")
		exit()

	msgFromSupervisor = sock.recv(size)
	if sys.getsizeof(msgFromSupervisor)>0:
		print("data sucessfully received from supervisor")
	else:
		print("data was not received from supervisor")
		exit()
	print("response from supervisor ", str(msgFromSupervisor)) 
	print("Recieved data from supervisor")
	return msgFromSupervisor

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

def supervisorConnect():
	supervisorIp = '127.0.0.1'
	supervisorPort = 9090
	size = 4098

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((supervisorIp, supervisorPort))
	return s

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
		

#Encrypting file using RSA
def encrypt_RSA(message, public_key):
	cipher = rsa.encrypt(message, public_key)
	return cipher

#Decryption using RSA
def decrypt_RSA(cipher_text, private_key):
	message = rsa.decrypt(cipher_text, private_key)
	return message

#Generating RSA keys
def generateRSAKeys():
	public_key, private_key = rsa.newkeys(512)

#Requesting public key of supervisor from CA
def requestPublicKeyFromCA(role):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	CA_ip = '127.0.0.1'
	CA_port = '7070'
	s.connect(CA_ip, CA_port)
	s.send("Request for public key of ", role)
	pub_key = s.recv(1024)
	return pub_key

#hashing the file
def hashFile(orderDetails):
	hashObject = hashlib.sha3_224()
	#Converting string to a byte objeect
	hashObject.update(orderDetails.encode("utf8"))
	digest = hashObject.digest()
	return digest

if __name__ == '__main__':
    app.run(use_reloader=True, debug=True)

