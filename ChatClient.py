# Echo client program
import socket
import sys
import select
from pyDes import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


HOST = '192.168.1.9'          # The remote host, as i am running the client as well 
                            # on the same system. i am putting it as localhost.
PORT = 9009 #65000                # The same port as used by the server
chatClientSocketList = []   # We need the list to keep iterating between local input
                            # and broadcasted messages.

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

print "Connected to the Chat Server.\n You can post messages in the chat room\n"
sys.stdout.write('[Me] '); sys.stdout.flush()

k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0",padmode=PAD_PKCS5)

#We read the keys from stored files.

#Clients private RSA key. This is client and henc private key used for Digital Signature.
f = open('cprkey.pem','r')
chatClientPrivateKey = RSA.importKey(f.read())
f.close()

#Servers public RSA key. We wil use this key to verify broadcasted message from teh server.
f = open('spckey.pem','r')
chatServerPublicKey = RSA.importKey(f.read())
f.close()

chatClientSigningObject = PKCS1_v1_5.new(chatClientPrivateKey)
chatClientVerifierObject = PKCS1_v1_5.new(chatServerPublicKey)

#I am using this a delimiter between the Digital Signature and the message being sent
magicString = '12DEADBEEF21'

#Counter for messages sent from the count. 
#The other users in the chat room can deduce a loss in the intermediate message.
msgCounter = 0

while 1:                    #We need the loop to keep the chat client alive
    chatClientSocketList = [sys.stdin, s]

    # Get the list sockets which are readable
    #ready_to_read,ready_to_write,in_error = select.select(chatClientSocketList , [], [])

    for sock in chatClientSocketList:             
        if sock == s:
            # incoming message from remote server, s
            data = sock.recv(2048)

            if not data :
                print '\nDisconnected from chat server'
                sys.exit()
            else :
                #we have to extract teh data part first :). We had some stupid stuff added
                sender,temp,msg = data.partition('=')
                #print "%s : %s"
                
                if magicString in msg:
                    #First verify the sign/origination of the message [verifying if the server actually broadcasted the message]
                    firstSignature,temp,recvEncMsg = msg.partition(magicString)
                    recvEncMsgHash = SHA256.new(recvEncMsg)

                    if chatClientVerifierObject.verify(recvEncMsgHash, firstSignature):
                        #print "The signature is authentic."
                        decryptedData = k.decrypt(recvEncMsg)
                    
                        printMsg = sender + ':'+ decryptedData
                            #print '%s: %s' % (sender,decryptedData)
                        sys.stdout.flush();
                        sys.stdout.write(printMsg)  ;sys.stdout.flush();              
                        sys.stdout.write('[Me] ');    
                        #else:
                            #print "The signature is not authentic."
                            #continue                    
                    else:
                        sys.stdout.write('IL The message is tampered. Cannot verify the remote host:%s s Digital signature. ' % sender);  sys.stdout.flush(); 
                        sys.stdout.write('[Me] '); 
                        
                else :
                    #it could be two things, 1.servers broadcast message 2. someone junk guy broadcasting stuff
                    #we will try to handle both
                    if 'ChatRoomMsg' in msg  : 
                        firstSignature,temp,recvEncMsg = msg.partition('21DEADBEEF12')
                        recvEncMsgHash = SHA256.new(recvEncMsg)

                        if chatClientVerifierObject.verify(recvEncMsgHash, firstSignature):
                            #print "The signature is authentic."
                        
                            sys.stdout.flush()                  
                            sys.stdout.write( recvEncMsg) ;sys.stdout.flush(); 
                            sys.stdout.write('[Me] '); 
                        else:
                            sys.stdout.write('OL1 The message is tampered. Cannot verify the remote host:%s s Digital signature. ' % sender);  sys.stdout.flush(); 
                            sys.stdout.write('[Me] ');
                    else :
                        sys.stdout.write('OL2 Cannot verify the remote host. Messg=' + data );  sys.stdout.flush(); 
                        sys.stdout.write('[Me] '); 

        else :
            # user entered a message
            sys.stdout.flush() 
            msg = sys.stdin.readline()            
            msg = str(msgCounter) + ':'+ msg

            #print "msg is" + msg
            sys.stdout.write('[Me] '); 
            
            #Encrypt the signed message
            encryptedMsg = k.encrypt(msg.encode('ascii'))
            #print "encrypted msg is" +  encryptedMsg
            
            #Hash of the encrypted signed message
            #Sign the new Hash 
            #Combine the Sign and the encrypted signed message
            enc_msg_hash = SHA256.new(encryptedMsg)
            enc_msg_sig = chatClientSigningObject.sign(enc_msg_hash)
            fin_trans_msg = enc_msg_sig + magicString + encryptedMsg

            #print "final trans mesg is:" +fin_trans_msg
            s.send(fin_trans_msg)
            msgCounter = msgCounter+1

               