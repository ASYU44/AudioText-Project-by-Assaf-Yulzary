# imports
import socket
import threading
import pickle
import pymongo
import datetime
import os
import rsa
from cryptography.fernet import Fernet
import hashlib
import random

"""
Errors:
001 - Message Type Couldn't Be Recognized
002 - Client Program Was Forcibly Closed
003 - Server In Target Ip And Target Port Is Not Ready To Any Client Acceptance
004 - Incorrect Input In Target Port Or Target Ip
005 - An Existing Connection Was Forcibly Closed By The Remote Host
006 - File In 'server_assets' Is Not Exist
007 - Length Field Is Not Int
008 - Hash Value Does Not Match With Hashed Data
009 - Server Program Closed Before Binding
010 - Server Does Not Have Text Channels
011 - Length Field Not Big Enough
012 - Length Of Message Does Not Matching The Length Field
013 - File In 'client_assets' Is Not Exist
014 - Server Does Not Have Audio Channels
015 - Message Sent From Unknown Address 
"""

# global variables
active_threads = []
ports_in_use = []
ALL_MESSAGES_VISIBLE = True  # True if you want to view messages log
lock = threading.Lock()

# rsa variables
publicKey, privateKey = rsa.newkeys(512)  # generate keys
publicKey_bytes = publicKey.save_pkcs1()  # convert public key to bytes for sending

# Mongo DataBase
mongo_client = pymongo.MongoClient("mongodb://localhost:27017/")
audiotext_db = mongo_client["AudioText"]
users = audiotext_db.audiotext_users["accounts"]  # creating the Data base for accounts data
channels = audiotext_db.audiotext_channels["channels"]  # creating the Data base for channels data


# classes
class Message:
    def __init__(self, sender_name: str, message: str) -> None:
        self.sender_name = sender_name
        self.message = message
        self.time_sent = datetime.datetime.now()

    def __str__(self) -> str:
        return f'\n{self.sender_name}: {self.time_sent.strftime("%d/%m/%Y %H:%M")}\n"{self.message}"\n'


class AudioChannel:
    def __init__(self, audio_channel: dict or str) -> None:
        if type(audio_channel) == dict:
            self.name = audio_channel['name']
        else:
            self.name = audio_channel
        self.active_people = []

    def str_active_people(self) -> str:
        str_active_people = ''
        for active_user in self.active_people:
            str_active_people += active_user.user['username'] + ';'
        return str_active_people[:-1]


class TextChannel:
    def __init__(self, text_channel: dict or str) -> None:
        if type(text_channel) == dict:
            self.name = text_channel['name']
        else:
            self.name = text_channel
        try:
            with open(f"server_assets\\{self.name}.pickle", "x"):
                print(f'server_assets\\{self.name}.pickle created')
        except FileExistsError:
            pass

    def __str__(self) -> str:
        lines = output_pickle(self.name)
        str_messages = ''
        for line in lines:
            str_messages += str(line)
        return f'Text Channel Name: server_assets\\{self.name}.pickle\n{str_messages}'

    def add_message(self, message: Message) -> bool:
        lines = []

        # reading all line in pickle
        if not os.path.exists(f"server_assets\\{self.name}.pickle"):
            print(f'Error : 006 file {self.name}.pickle in server_assets is not exist')
            return False
        with open(f"server_assets\\{self.name}.pickle", 'rb') as read:
            while True:
                try:
                    lines.append(pickle.load(read))
                except EOFError:
                    break

        # writing it all back
        with open(f"server_assets\\{self.name}.pickle", 'wb') as write:
            for line in lines:
                pickle.dump(line, write)
            pickle.dump(message, write)
        return True


class Client:
    def __init__(self, addr: tuple[str, int], sock_tcp: socket, index: int) -> None:
        self.addr = addr
        ports_in_use.append(self.addr[1])
        self.udp_port = random.randint(50000, 60000)
        while self.udp_port in ports_in_use:
            self.udp_port = random.randint(50000, 60000)
        ports_in_use.append(self.udp_port)
        self.sock_tcp = sock_tcp
        self.index = index
        self.text_channel = 'No Channel'
        self.audio_channel = ''
        self.user = {}
        self.fernet = None
        self.symmetric_key = b''
        self.sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_udp.settimeout(0.02)
        self.sock_udp.bind(('0.0.0.0', self.udp_port))

    def decrypt(self, encrypted_data: bytes, visible: bool) -> bytes or str:
        lock.acquire()
        if encrypted_data.split(b'~', 1)[0] == b'PRVC':
            data = b'PRVC~' + rsa.decrypt(encrypted_data[5:], privateKey)
            random_number = b'No Random Number'
            hash_value = b'No Hash'
        else:
            data = self.fernet.decrypt(encrypted_data)
            hash_value, data = data.split(b'~', 1)
            if hash_value != hashlib.sha256(self.symmetric_key + data).hexdigest().encode():
                print('Error 008 : Hash value does not match with hashed data')
                self.send_with_size_tcp(f"ERRR~008~'{hash_value}' does not match with hashed data")
                return 'Error'
            random_number = data.split(b'~')[-1]  # get random number
            data = data[:-(len(random_number) + 1)]  # remove random number
        if visible or ALL_MESSAGES_VISIBLE:
            print(f'\n******************************************')
            print(f'Receive from {self.addr[0]}:{self.addr[1]} length - {str(len(encrypted_data)).zfill(8)}')
            print(f'Hash Value - {hash_value.decode()}')
            print(f'Random number - {random_number.decode()}')
        try:
            if visible or ALL_MESSAGES_VISIBLE:
                print(f'data - {data[:1000].decode()}')
                print('******************************************\n')
            lock.release()
            return data.decode()
        except (UnicodeDecodeError, AttributeError):
            if visible or ALL_MESSAGES_VISIBLE:
                print(b'data - ' + data[:1000])
                print('******************************************\n')
            lock.release()
            return data

    def recv_udp(self, visible: bool = False) -> str or bytes:
        try:
            encrypted_data, addr = self.sock_udp.recvfrom(2916)
            if addr != self.addr:
                print(f'Error 015 : Message sent from unknown address')
                return 'Not Error'
            if encrypted_data == b'':
                return 'Error'
            if addr != self.addr:
                print(f'Error 015 : Message sent from unknown address')
                return 'Not Error'
            return self.decrypt(encrypted_data, visible)
        except socket.timeout:
            return 'Not Error'
        except socket.error:
            print(f'Error 002 : Client [{self.index}] program was forcibly closed')
            return 'Error'

    def recv_by_size_tcp(self, visible: bool = False) -> str or bytes:
        try:
            data_len_bytes = self.sock_tcp.recv(9)
            if data_len_bytes == b'':
                return 'Error'
            data_len = int(data_len_bytes[:-1])
            encrypted_data = self.sock_tcp.recv(data_len)
            return self.decrypt(encrypted_data, visible)
        except socket.timeout:
            return 'Not Error'
        except socket.error:
            print(f'Error 002 : Client [{self.index}] program was forcibly closed')
            return 'Error'
        except ValueError:
            print('Error 007 : Length field is not int')
            self.send_with_size_tcp(f"ERRR~007~Length field is not int")
            return 'Not Error'

    def encrypt(self, data: str or bytes, visible: bool) -> bytes:
        lock.acquire()
        if type(data) != bytes:
            data = data.encode()
        if data.split(b'~')[0] != b'PUBS' and data.split(b'~')[0] != b'WATS':
            random_number = b'~' + str(random.randrange(1000)).encode()
            hash_value = hashlib.sha256(self.symmetric_key + data + random_number).hexdigest().encode()
            encrypted_data = self.fernet.encrypt(hash_value + b'~' + data + random_number)
        else:
            hash_value = b'No Hash'
            random_number = b'~No Random Number'
            encrypted_data = data

        if visible or ALL_MESSAGES_VISIBLE:
            print(f'\n******************************************')
            print(f'Send to {self.addr[0]}:{self.addr[1]} length - {str(len(encrypted_data)).zfill(8)}')
            print(f'Hash Value - {hash_value.decode()}')
            print(f'Random number - {random_number[1:].decode()}')
            try:
                print(f'data - {data[:1000].decode()}')
            except (UnicodeDecodeError, AttributeError):
                print(b'data - ' + data[:1000])
            print('******************************************\n')
        lock.release()
        return encrypted_data

    def send_udp(self, data: str or bytes, visible: bool = False) -> None:
        """
        Sending message to client in UDP socket with length field and encrypted

        param client: client
        param data: data to send to server in string or bytes
        param visible: print the message parameters if True
        """

        encrypted_data = self.encrypt(data, visible)
        self.sock_udp.sendto(encrypted_data, self.addr)

    def send_with_size_tcp(self, data: str or bytes, visible: bool = False) -> None:
        """
        Sending message to client in TCP socket with length field and encrypted

        param client: client
        param data: data to send to server in string or bytes
        param visible: print the message parameters if True
        """
        try:
            encrypted_data = self.encrypt(data, visible)
            message_length = str(len(encrypted_data)).zfill(8)
            self.sock_tcp.send(message_length.encode() + b'~' + encrypted_data)
        except socket.error as err:
            print(err)

    def __str__(self) -> str:
        if self.user != {}:
            return f'\n[{self.index}]' \
                   f' TCP {self.addr[0]}:{self.addr[1]} UDP {self.addr[0]}:{self.udp_port}\n {self.user}\n'
        return f'\n[{self.index}] {self.addr[0]}:{self.addr[1]}'


class Server:
    def __init__(self) -> None:
        self.sock_tcp = None
        self.port = 60000
        users.update_many({"online": 'Y'}, {'$set': {"online": 'N'}})

        self.ip = '0.0.0.0'  # change to address you want
        self.bind_server(self.port)  # write here the port you want
        print(f'Server binding to address - {socket.gethostbyname(socket.gethostname())}:{self.port}')
        self.connections = []
        self.text_channels = {}
        self.audio_channels = {}
        self.kill_all = False

        for text_channel in list(channels.find({'is_text': True})):
            self.text_channels[text_channel['name']] = TextChannel(text_channel)

        for audio_channel in list(channels.find({'is_text': False})):
            self.audio_channels[audio_channel['name']] = AudioChannel(audio_channel)

        self.accept_clients()  # main loop

    def bind_server(self, port: int = -1) -> None:
        if port != -1:
            try:
                self.port = port
                self.sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock_tcp.bind((self.ip, self.port))
                return
            except (BaseException, socket.error):
                print(f"Couldn't bind to address - {self.ip}:{self.port}")
        # else and except
        while True:
            try:
                self.port = int(input('Enter port number to run on --> '))

                self.sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock_tcp.bind((self.ip, self.port))
                return
            except socket.error:
                print(f"Couldn't bind to port - {socket.gethostbyname(socket.gethostname())}:{self.port}")
            except KeyboardInterrupt:
                print('Error 009 : Program closed before binding')

    def accept_clients(self) -> None:
        index = 0
        self.sock_tcp.listen()
        # Creating the threads for new clients
        try:
            while not self.kill_all:
                client_sock, addr = self.sock_tcp.accept()
                client_sock.settimeout(0.1)
                index += 1
                if len(self.connections) < 20:
                    active_thread = threading.Thread(target=self.handle_client, args=(addr, client_sock, index)).start()
                    active_threads.append(active_thread)
                else:
                    client = Client(addr, client_sock, index)
                    print(f'Client [{index}] disconnected because there are too many active clients')
                    client.send_with_size_tcp('WATS')
                    client_sock.close()
        except KeyboardInterrupt:
            print('Error 005 : An existing connection was forcibly closed by the remote host')
        self.close_server()

    def handle_request(self, client: Client, data: str or bytes) -> bool:
        if type(data) == str:
            fields = data.split('~')
        else:
            fields = data.split(b'~')
            fields[0] = fields[0].decode()
        if fields[0] == 'EXIT':
            client.send_with_size_tcp('EXTR')
            return True
        elif fields[0] == 'DEFC':
            client.user["deafened"] = fields[1]
            if fields[1] == 'Y':
                print(f'Client [{client.index}] now is deafened')
            elif fields[1] == 'N':
                print(f'Client [{client.index}] now is undeafened')
            users.update_one({"username": client.user['username']}, {'$set': {'deafened': fields[1]}})
        elif fields[0] == 'NMSC':
            if client.text_channel == 'No Channel':
                print('Error 010 : Server does not have text channels')
                return False
            message = Message(client.user['username'], fields[1])
            print(f'Client [{client.index}] sent in {client.text_channel} "{fields[1]}"')
            self.text_channels[client.text_channel].add_message(message)
            for other_client in self.connections:
                messages = output_pickle(client.text_channel)
                if other_client.text_channel == client.text_channel:
                    str_messages = ''
                    for message in messages:
                        str_messages += '~' + message.sender_name + ';' + message.message + ';' \
                                        + message.time_sent.strftime("%d/%m/%Y %H:%M")
                    other_client.send_with_size_tcp(f'MSGS' + str_messages)
        elif fields[0] == 'TXTC':
            client.text_channel = fields[1]
            print(f'[{client.index}] Opened text channel {client.text_channel}')
            messages = output_pickle(client.text_channel)
            str_messages = ''
            for message in messages:
                str_messages += '~' + message.sender_name + ';' + message.message + ';'\
                                + message.time_sent.strftime("%d/%m/%Y %H:%M")
            client.send_with_size_tcp(f'MSGS' + str_messages)
        elif fields[0] == 'AUDC':
            audio_bytes = b'~'.join(fields[1:])
            for other_client in self.audio_channels[client.audio_channel].active_people:
                if other_client != client and other_client.user['deafened'] == 'N':
                    other_client.send_udp(b'AUDS~' + audio_bytes)
        elif fields[0] == 'JONC':
            client.audio_channel = fields[1]
            if fields[1] == '':
                self.audio_channels[fields[2]].active_people.remove(client)
            else:
                if fields[2] != '':
                    self.audio_channels[fields[2]].active_people.remove(client)
                if client not in self.audio_channels[fields[1]].active_people:
                    self.audio_channels[fields[1]].active_people.append(client)
            audio_channels_str = ''
            for audio_channel in self.audio_channels.keys():
                audio_channels_str += f'~{audio_channel}'
                for people_online in self.audio_channels[audio_channel].active_people:
                    audio_channels_str += ';' + people_online.user['username']

            for other_client in self.connections:
                if other_client.user != {}:
                    other_client.send_with_size_tcp('ACNS' + audio_channels_str)
        elif fields[0] == 'MUTC':
            client.user["muted"] = fields[1]
            if fields[1] == 'Y':
                print(f'Client [{client.index}] now is muted')
            elif fields[1] == 'N':
                print(f'Client [{client.index}] now is unmuted')
            users.update_one({"username": client.user['username']}, {'$set': {'muted': fields[1]}})
        elif fields[0] == 'SGNC':
            if users.find_one({"username": fields[1]}) is None:
                client.user = {"username": fields[1], "password": hashlib.sha256(fields[2].encode()).hexdigest(),
                                  "muted": 'Y', "deafened": 'Y', "operator": 'N', "online": 'Y'}
                users.insert_one(client.user)
                client.send_with_size_tcp(f'LOGS~Y~{client.user["operator"]}~{client.user["muted"]}~'
                                          f'{client.user["deafened"]}')
                print(f'Client [{client.index}] signed up as user {fields[1]}')
                online_members = list(users.find({"online": 'Y'}))
                online_members_names = ''
                for member in online_members:
                    online_members_names += '~' + member['username']

                # sending all online users that the client is online
                for online_member in self.connections:
                    if online_member.user != {}:
                        online_member.send_with_size_tcp(f'ONLS' + online_members_names)
                # sending client all text_channels
                if self.text_channels == {}:
                    print('Error 010 : server does not have text channels')
                    client.send_with_size_tcp(f'ERRR~010~server does not have text channels')
                    return True
                else:
                    client.send_with_size_tcp(f'TCNS~' + '~'.join(self.text_channels.keys()))

                if self.audio_channels == {}:
                    print('Error 014 : server does not have audio channels')
                    client.send_with_size_tcp(f'ERRR~014~server does not have audio channels')
                    return True
                else:
                    audio_channels_str = ''
                    for audio_channel in self.audio_channels.keys():
                        audio_channels_str += f'~{audio_channel}'
                        for people_online in self.audio_channels[audio_channel].active_people:
                            audio_channels_str += ';' + people_online.user['username']
                    client.send_with_size_tcp(f'ACNS' + audio_channels_str)
            else:
                client.send_with_size_tcp(f'LOGS~S')

        elif fields[0] == 'LOGC':
            if users.find_one({"username": fields[1],
                               "password": hashlib.sha256(fields[2].encode()).hexdigest()}) is not None:
                client.user = users.find_one({"username": fields[1]})
                if client.user['online'] == 'N':
                    client.send_with_size_tcp(f'LOGS~Y~{client.user["operator"]}~{client.user["muted"]}~'
                                               f'{client.user["deafened"]}')
                    users.update_one({"username": client.user['username']}, {'$set': {'online': 'Y'}})
                    client.user['online'] = 'Y'
                    print(f'Client [{client.index}] logged as user {fields[1]}')

                    # sending the online users to all online users
                    online_members = list(users.find({"online": 'Y'}))
                    online_members_names = ''
                    for member in online_members:
                        online_members_names += '~' + member['username']

                    # sending all online users that the client is online
                    for online_member in self.connections:
                        if online_member.user != {}:
                            online_member.send_with_size_tcp(f'ONLS' + online_members_names)
                    # sending client all text_channels
                    if self.text_channels == {}:
                        print('Error 010 : server does not have text channels')
                        client.send_with_size_tcp(f'ERRR~010~server does not have text channels')
                        return True
                    else:
                        client.send_with_size_tcp(f'TCNS~' + '~'.join(self.text_channels.keys()))

                    if self.audio_channels == {}:
                        print('Error 014 : server does not have audio channels')
                        client.send_with_size_tcp(f'ERRR~014~server does not have audio channels')
                        return True
                    else:
                        audio_channels_str = ''
                        for audio_channel in self.audio_channels.keys():
                            audio_channels_str += f'~{audio_channel}'
                            for people_online in self.audio_channels[audio_channel].active_people:
                                audio_channels_str += ';' + people_online.user['username']
                        client.send_with_size_tcp(f'ACNS' + audio_channels_str)

                else:  # username and password matching but this user is online in other place already
                    client.send_with_size_tcp(f'LOGS~A')
            else:  # username and password not matching
                client.send_with_size_tcp(f'LOGS~N')
        elif fields[0] == 'ERRR':
            print(f"Client Error {fields[1]} - {fields[2]}")
        else:
            print(f"Error 001 : '{fields[0]}' Message type couldn't be recognized")
            client.send_with_size_tcp(f"ERRR~001~'{fields[0]}' Message type couldn't be recognized")
        return False

    def handle_client(self, addr: tuple[str, int], sock: socket, index: int) -> None:
        client = Client(addr, sock, index)
        self.connections.append(client)
        print(f'There are {len(self.connections)} clients')
        print(f'[{client.index}] {client.addr[0]}:{client.addr[1]} Connected')
        client.send_with_size_tcp(b'PUBS~' + publicKey_bytes)
        print(f'Public key shared to client number [{client.index}]')

        try:
            data = client.recv_by_size_tcp()
            fields = data.split('~')
            if fields[0] == 'PRVC':
                client.symmetric_key = fields[1].encode()
                client.fernet = Fernet(client.symmetric_key)
                print(f'Symmetric key shared from client number [{client.index}]')
                client.send_with_size_tcp(f'PORC~{client.addr[1]}~{client.udp_port}')
                client.sock_tcp.settimeout(0.02)
                while True:
                    data = client.recv_by_size_tcp()
                    if data == 'Error':
                        break
                    elif data == 'Not Error':
                        pass
                    else:
                        if self.handle_request(client, data):
                            print(f'Client [{client.index}] ask for disconnection')
                            break

                    if client.audio_channel != '':
                        data = client.recv_udp()
                    else:
                        data = 'Not Error'
                    if data == 'Error':
                        break
                    elif data == 'Not Error':
                        pass
                    else:
                        if self.handle_request(client, data):
                            print(f'Client [{client.index}] ask for disconnection')
                            break

                    if self.kill_all:
                        print(f'Connection With Client [{client.index}] Closed By Server')
                        break
        except socket.error:
            print(f'Error 002 : Client [{client.index}] program was forcibly closed')
        client.sock_tcp.close()
        client.sock_udp.close()
        ports_in_use.remove(client.udp_port)
        ports_in_use.remove(client.addr[1])
        if client.user != {}:
            users.update_one({"username": client.user['username']}, {'$set': {'online': 'N'}})
            if client.audio_channel != '':
                self.audio_channels[client.audio_channel].active_people.remove(client)
        self.connections.remove(client)

        # sending the online users to all online users
        online_members = list(users.find({"online": 'Y'}))
        online_members_names = ''
        for member in online_members:
            online_members_names += '~' + member['username']

        audio_channels_str = ''
        for audio_channel in self.audio_channels.keys():
            audio_channels_str += f'~{audio_channel}'
            for people_online in self.audio_channels[audio_channel].active_people:
                audio_channels_str += ';' + people_online.user['username']

        for online_member in self.connections:
            if online_member.user != {}:
                online_member.send_with_size_tcp('ONLS' + online_members_names)
                if client.audio_channel != '':
                    online_member.send_with_size_tcp('ACNS' + audio_channels_str)

        print(f'There are {len(self.connections)} clients')

    def close_server(self) -> None:
        for thread in active_threads:
            thread.join()
        self.sock_tcp.close()


def output_pickle(pickle_name: str) -> list:
    """
    Get a List of all the lines in the pickle file

    param pickle_name: name of the pickle file
    return: list of all values dumped to this pickle
    """

    if not os.path.exists(f"server_assets\\{pickle_name}.pickle"):
        print(f'Error : 006 file {pickle_name}.pickle in server_assets is not exist')
        return []
    lines = []

    # reading all line in pickle
    with open(f"server_assets\\{pickle_name}.pickle", 'rb') as read:
        while True:
            try:
                lines.append(pickle.load(read))
            except EOFError:
                # to check how many lines in pickle
                # print(f'The Number of Lines in server_assets\\{pickle_name}.pickle is {len(lines)}')
                break

    # writing it back
    with open(f"server_assets\\{pickle_name}.pickle", 'wb') as write:
        for line in lines:
            pickle.dump(line, write)

    return lines


if __name__ == '__main__':
    #channels.insert_one({'name': 'text_channel 2', 'is_text': True})
    #channels.insert_one({'name': 'text_channel', 'is_text': True})
    #channels.insert_one({'name': 'spam', 'is_text': True})
    #channels.insert_one({'name': 'voice_channel', 'is_text': False})
    #channels.insert_one({'name': 'voice_channel 1', 'is_text': False})
    #channels.insert_one({'name': 'voice_channel 3', 'is_text': False})
    if len(list(channels.find({'is_text': True}))) > 0 and len(list(channels.find({'is_text': False}))) > 0:
        server = Server()
    else:
        print('Error 010 : server does not have text channels')
