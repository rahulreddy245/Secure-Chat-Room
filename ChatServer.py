# chat_server.py
 
import sys
import socket
import select
from pyDes import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

chatServerHOST = '192.168.1.9' 
chatServerSocketList = []           #list of all sockets in the ChatServer application. Used during broadcasting.
chatServerRecvBuffer = 4096 
chatServerPort = 9009

k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0",padmode=PAD_PKCS5)

f = open('sprkey.pem','r')
chatServerPrivateKey = RSA.importKey(f.read())
f.close()

f = open('cpckey.pem','r')
chatClientPublicKey = RSA.importKey(f.read())
f.close()

chatServerSigningObject = PKCS1_v1_5.new(chatServerPrivateKey)
chatServerVerifierObject = PKCS1_v1_5.new(chatClientPublicKey)

def chat_server():

    chatServerServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #Creating the Server Socket
    chatServerServerSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    chatServerServerSocket.bind((chatServerHOST, chatServerPort))               #binding the socket to the host
    chatServerServerSocket.listen(10)                                           #Listening for connections.
 
    #Creating the list of all sockets in the ChatServer application.
    chatServerSocketList.append(chatServerServerSocket)
 
    #Log in the Chatservers console about the creation and starting event.
    print "ChatServerMsg :ChatRoom has been created and started on the port " + str(chatServerPort)
 
    while 1:

        # Seggregating the active Sockets. We can read through those socket's "FD"
        # Also set time_out  = 0 ==> for polling always and never blocking.
        chatServerReadActive,chatServerWriteActive,chatServerError = select.select(chatServerSocketList,[],[],0)
      
        for sockfd in chatServerReadActive:
            #Case : Server has received a join request .
            if sockfd == chatServerServerSocket: 
                chatServerClientSockFd, chatServerClientAddr = chatServerServerSocket.accept()
                chatServerSocketList.append(chatServerClientSockFd)
                #Log in the Chatservers console about the new user .
                print "ChatServerMsg :(%s, %s) is in the ChatRoom" % chatServerClientAddr
                
                broadCastMsg = "ChatRoomMsg : [%s:%s]  as a new participent\n" % chatServerClientAddr
                #print "BDCMsg = " + broadCastMsg
                broadCastMsg_hash = SHA256.new(broadCastMsg)
                broadCastMsg_sig = chatServerSigningObject.sign(broadCastMsg_hash)
                fin_broadCastMsg = str(broadCastMsg_sig + '21DEADBEEF12' + broadCastMsg)

                #Calling chatRoomBroadcaster to broadcast the message to the users in chat room. This way they are aware of the event.
                chatRoomBroadcaster(chatServerServerSocket, chatServerClientSockFd, '[ From SERVER ]=' + fin_broadCastMsg);             
            #Case : it is not a connection request. It is a message from a client.
            else:
                # Receive the data from the client, 
                try:
                    # receiving data from the socket.
                    chatRoomData = sockfd.recv(chatServerRecvBuffer)
                    if chatRoomData:
                        #Case 2.1 There is some data from the socket.
                        #print "chat data:" + chatRoomData
                        ##
                        #check for clients signature and message integrity
                        #First verify the sign/origination of the message [verifying if the server actually broadcasted the message]
                        firstSignature,magicnumber,recvEncMsg = chatRoomData.partition('12DEADBEEF21')
                        recvEncMsgHash = SHA256.new(recvEncMsg)

                        if chatServerVerifierObject.verify(recvEncMsgHash, firstSignature):
                            print "Message's sender/Client "+ str(sockfd.getpeername()) +" signature verified. " 
                            
                            #Hash of the encrypted signed message
                            #Sign the new Hash 
                            #Combine the Sign and the encrypted signed message
                            enc_msg_hash = SHA256.new(recvEncMsg)
                            enc_msg_sig = chatServerSigningObject.sign(enc_msg_hash)
                            fin_trans_msg = str(enc_msg_sig + '12DEADBEEF21' + recvEncMsg)
                           
                            chatRoomBroadcaster(chatServerServerSocket, sockfd, "\r" + '[' + str(sockfd.getpeername()) + ']=' + fin_trans_msg)  
                                
                        else:
                            print "The signature of Sender Client:"+str(sockfd.getpeername())+" could not be verfied. So not broadcasting the message" 
        
                       
                    else:
                        #Case 2.2 Socket is broken/closed. Remove the socket from the sockList.    
                        if sockfd in chatServerSocketList:
                            chatServerSocketList.remove(sockfd)

                        #We inform others about the event "lost connection to the sock".
                        chatRoomBroadcaster(chatServerServerSocket, sockfd, "ChatRoomMsg :Participents (%s, %s), exited the chatRoom \n" % chatServerClientAddr) 
                        continue 
                # If we have some unexpected event , like the client exits suddenly. 
                except:
                    #chatRoomBroadcaster(chatServerServerSocket, sockfd, "ChatRoomMsg :Participent (%s, %s), is gone\n" % chatServerClientAddr)
                    continue

    chatServerServerSocket.close()
    
#Routine used to broadcase messages to all the users in the chat Room
def chatRoomBroadcaster (chatServerServerSocket, sockfd, message):
    #Broadcasting requires us to loop through the chatServerServerSocket to process all the active sockets' FD
    #and send the message to individual sockets FD.
    
    #print "isndie broadcaseter message ening sent is: " + message
    for socket in chatServerSocketList:
        # We have to send the message to all the users in the char room except
        if socket != chatServerServerSocket and socket != sockfd :    # the user who sent the message and the server.
            try :
                socket.send(message)
            except :
                #If there is exception, means client is gone. So close the connection.
                socket.close()
                #And then clean the socketList. So we dont process it anymore.
                if socket in chatServerSocketList:
                    chatServerSocketList.remove(socket)
 
if __name__ == "__main__":

    sys.exit(chat_server()) 