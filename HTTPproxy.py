from socket import *
from urlparse import urlparse
import threading
import requests
import hashlib
from StringIO import StringIO
from httplib import HTTPResponse
import optparse

# initialize server socket to listen from client
serverSocket = socket(AF_INET, SOCK_STREAM)
serverSocket.bind(('localhost', 2100))
serverSocket.listen(100)
html_rsp = '<!DOCTYPE html>\r\n<html>\r\n<body>\r\n\r\n<h1>content blocked</h1>\r\n\r\n</body>\r\n</html>\r\n\r\n'

# parse the api from command line
parser = optparse.OptionParser()
parser.add_option('-k', dest='api', type='string')
(options, args) = parser.parse_args()
api = options.api


def thread(connectionSocket):
    ''' A single thread that handle the interation with client and server '''
    messageToServer = ''
    clientMessage = connectionSocket.recv(1024)
    clientMessageLines = clientMessage.splitlines()

    # check if \r\n is added correctly
    if len(clientMessageLines) != 1 and clientMessageLines[-1]:
        connectionSocket.send('HTTP/1.0 400 Bad Request\r\n\r\n')
        connectionSocket.close()
        return

    requestLine = clientMessageLines[0]
    if requestLine.startswith('GET'):
        # check request line format
        requestLineTokens = requestLine.split()
        if len(requestLineTokens) != 3 or not requestLineTokens[2].startswith('HTTP/'):
            connectionSocket.send('HTTP/1.0 400 Bad Request\r\n\r\n')
            connectionSocket.close()
            return

        parsed_url = urlparse(requestLineTokens[1])
        serverPort = 80
        if parsed_url.scheme != 'http':
            connectionSocket.send('HTTP/1.0 400 Bad Request\r\n\r\n')
            connectionSocket.close()
            return
        if parsed_url.port is not None:
            serverPort = parsed_url.port
        serverName = parsed_url.hostname
        messageToServer += 'GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n'.format(
            parsed_url[2], serverName)

        # add the header to the messageToServer
        i = 1
        while i < len(clientMessageLines) - 1:
            headerLineTokens = clientMessageLines[i].split()
            # check header line format
            if len(headerLineTokens) > 0 and not headerLineTokens[0].startswith('Connection:') and not headerLineTokens[0].startswith('Host:'):
                messageToServer += clientMessageLines[i] + '\r\n'
            i += 1
        messageToServer += '\r\n'

        # Establish connection with server and send the message to server
        clientSocket = socket(AF_INET, SOCK_STREAM)
        try:
            clientSocket.connect((serverName, serverPort))
        except Exception:
            connectionSocket.send('HTTP/1.0 400 Bad Request\r\n\r\n')
            connectionSocket.close()
            return
        clientSocket.send(messageToServer)

        # get the response from server
        fullRsp = ''
        while True:
            rsp = clientSocket.recv(1024)
            if len(rsp) <= 0:
                break
            fullRsp += rsp

        clientSocket.close()
        # retrieve the body part from the response and convert it into MD5 checksum
        body = getBody(fullRsp)
        hash = hashlib.md5(body).hexdigest()

        # Send file to virus total and get the response
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api, 'resource': hash}
        try:
            VT_rsp = requests.get(url, params=params).json()
        except Exception:
            connectionSocket.send(
                'HTTP/1.0 500 Virus Total Error\r\n\r\n')
            connectionSocket.close()
            return
        rsp_code = VT_rsp["response_code"]
        # Send content blocked html response if virus exists
        if rsp_code == 1 and VT_rsp["positives"] > 0:
            fullRsp = 'HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n' + html_rsp
        connectionSocket.send(fullRsp)
        connectionSocket.close()

    # If method not implemented is in the request line, send Not Implemented 501
    elif requestLine.startswith(('POST', 'PUT', 'DELETE', 'HEAD', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH')):
        connectionSocket.send('HTTP/1.0 501 Not Implemented\r\n\r\n')
        connectionSocket.close()

    else:
        connectionSocket.send('HTTP/1.0 400 Bad Request\r\n\r\n')
        connectionSocket.close()


def getBody(msg):
    ''' Get the entity body section of the http message '''
    class FakeSocket():
        def __init__(self, msg):
            self.file = StringIO(msg)

        def makefile(self, *args, **kwargs):
            return self.file

    source = FakeSocket(msg)
    rsp = HTTPResponse(source)
    rsp.begin()
    return rsp.read(len(msg))


processes_count = 0
# Start a process for every incoming connection
while processes_count <= 100:
    connectionSocket, addr = serverSocket.accept()
    p = threading.Thread(target=thread, args=[connectionSocket])
    p.start()
    processes_count += 1
serverSocket.close()
