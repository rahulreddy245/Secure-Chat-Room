# Echo client program
import socket
import sys
import select
from pyDes import *

HOST = '192.168.1.9'          # The remote host, as i am running the client as well 
                            # on the same system. i am putting it as localhost.
PORT = 9009 #65000                # The same port as used by the server
chatClientSocketList = []   # We need the list to keep iterating between local input
                            # and broadcasted messages.

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

print "Connected to the Chat Server.\n You can post messages in the chat room\n"
sys.stdout.write('[Me] '); sys.stdout.flush()


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
                decryptedData = msg
                
                printMsg = sender + ':'+ decryptedData
                #print '%s: %s' % (sender,decryptedData)
                sys.stdout.flush();
                sys.stdout.write(printMsg)  ;sys.stdout.flush();              
                sys.stdout.write('[Me] ');      
            
        else :
            # user entered a message
            sys.stdout.flush() 
            msg = sys.stdin.readline()            
            sys.stdout.write('[Me] '); 
            #encryptedMsg = k.encrypt(msg.encode('ascii'))
            s.send(msg)
               