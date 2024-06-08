#!/usr/bin/python3

# imports
import socket
import pygame
import rsa
from cryptography.fernet import Fernet
import hashlib
import random
import sys
import time
import pyaudio
import threading

pygame.init()
audio = pyaudio.PyAudio()
# default variables
display_width = 900  # 1200 default
MINIMUM_WIDTH = 916
MINIMUM_HEIGHT = 400
display_height = 600  # 800 default
SPECIAL_CHARACTERS = '!@#$%^&*()_-+= \\|]}[{`:",<.>/?\''
die = False
online_users = []
text_channels = []
audio_channels = {}
text_channel_messages = []
ALL_MESSAGES_VISIBLE = True  # True for view log
new_messages_num = -1

# Pyaudio variables
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 22050
CHUNK = 1024
stream = audio.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, output=True, frames_per_buffer=CHUNK)
# fonts
font_40 = pygame.font.Font(None, 40)
font_30 = pygame.font.Font(None, 30)
font_20 = pygame.font.Font(None, 20)

# Fernet variables
symmetric_key = Fernet.generate_key()  # getting symmetric key in bytes
fernet = Fernet(symmetric_key)  # convert symmetric key in bytes to symmetric key

try:
    # images
    login_screen = pygame.transform.scale(pygame.image.load('client_assets\\login.bmp'), (600, 400))
    unmute_icon = pygame.transform.scale(pygame.image.load("client_assets\\unmute.png"), (32, 32))
    mute_icon = pygame.transform.scale(pygame.image.load("client_assets\\mute.png"), (32, 32))
    undeafen_icon = pygame.transform.scale(pygame.image.load("client_assets\\undeafen.png"), (32, 32))
    deafen_icon = pygame.transform.scale(pygame.image.load("client_assets\\deafen.png"), (32, 32))

    # audio files
    deafen_sound = pygame.mixer.Sound('client_assets\\Voicy_AudioText Deafen.mp3')
    unmute_sound = pygame.mixer.Sound('client_assets\\Voicy_AudioText Unmute.mp3')
    mute_sound = pygame.mixer.Sound('client_assets\\Voicy_AudioText Mute.mp3')
    undeafen_sound = pygame.mixer.Sound('client_assets\\Voicy_AudioText Undeafen.mp3')

except FileNotFoundError:
    print("Error 013 : file in 'client_assets' is not exist")
    pygame.quit()
    time.sleep(4)  # wait before closing program
    sys.exit()


# classes
class Client:
    def __init__(self) -> None:
        """
        Creating Client
        """
        self.target_port = None
        self.target_ip = None
        self.udp_port = None
        self.username = ''
        self.server_publicK = None
        self.operator = False
        self.muted = True
        self.deafened = True
        self.logged_in = False
        self.text_channel = ''
        self.audio_channel = ''
        self.sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if testing:
            self.connect_to_server(port=60000, ip='127.0.0.1')  # write here your port and address
        else:
            self.connect_to_server()  # write here your port and address

        self.sending_thread = threading.Thread(target=self.send_audio, args=())
        self.receiving_thread = threading.Thread(target=self.recv_audio, args=())
        print(f"\nConnected to Server {self.target_ip}:{self.target_port}\n")

    def connect_to_server(self, port: int = -1, ip: str = '') -> None:
        """
        Connecting Client to Server

        port: target port, default is ''
        ip: target IP, default is -1
        """
        # system for fast connection
        if ip != '' and port != -1:
            self.target_ip = ip
            self.target_port = port
            try:
                self.sock_tcp.connect((self.target_ip, self.target_port))
                return
            except socket.error:
                print(f"Error 003 : No connection could be made because the target machine actively refused it")

        # system for IP and PORT input
        while True:
            try:
                self.target_ip = input('Enter IP address of server --> ')
                ip_fields = self.target_ip.split('.')

                # checking if there are 4 fields in the ip
                if len(ip_fields) != 4:
                    int('')
                # checking if all the ip fields are positive integers
                for field in ip_fields:
                    if int(field) < 0:
                        int('')

                self.target_port = int(input('Enter target port of server --> '))

                self.sock_tcp.connect((self.target_ip, self.target_port))
                return
            except socket.error:
                print(f"Error 003 : No connection could be made because the target machine actively refused it")
            except ValueError:
                print(f"Error 004 : Incorrect Input In Target Port Or Target Ip")
            except KeyboardInterrupt:
                print('\nError 002 : Program forcibly closed before connecting to Server')
                self.sock_tcp.close()
                self.sock_udp.close()
                stream.stop_stream()
                stream.close()
                audio.terminate()
                pygame.quit()
                sys.exit()

    def encrypt(self, data: bytes or str, visible: bool) -> bytes:
        if type(data) != bytes:
            data = data.encode()
        if data.split(b'~')[0] == b'PRVC':
            encrypted_data = b'PRVC~' + rsa.encrypt(symmetric_key, self.server_publicK)
            print(f'Symmetric key "{symmetric_key.decode()}" shared with Server')
            hash_value = b'No Hash'
            random_number = b'~No Random Number'
        else:
            random_number = b'~' + str(random.randrange(1000)).encode()
            hash_value = hashlib.sha256(symmetric_key + data + random_number).hexdigest().encode()
            encrypted_data = fernet.encrypt(hash_value + b'~' + data + random_number)

        if visible or ALL_MESSAGES_VISIBLE:
            print('\n******************************************')
            print('Send length - ' + str(len(encrypted_data)).zfill(8))
            print(f'Hash Value - {hash_value.decode()}')
            print(f'Random number - {random_number[1:].decode()}')
            try:
                print(f'data - {data[:1000].decode()}')
            except (UnicodeDecodeError, AttributeError):
                print(b'data - ' + data[:750])
            print('******************************************\n')

        return encrypted_data

    def decrypt(self, encrypted_data: bytes, visible: bool) -> bytes or str:
        """
        Decrypting data if needed and print message properties when visible is True
        param encrypted_data: encrypted data
        param visible: print the message parameters if True
        return: decrypted_data in string or bytes
        """
        if encrypted_data[:4] == b'PUBS' or encrypted_data == b'WATS':
            print(f'Server shared his public key')
            data = encrypted_data
            hash_value = b'No Hash'
            random_number = b'No Random Number'
        else:
            data = fernet.decrypt(encrypted_data)
            hash_value, data = data.split(b'~', 1)
            if hash_value != hashlib.sha256(symmetric_key + data).hexdigest().encode():
                print('Error 008 : Hash value does not match with hashed data')
                self.send_with_size_tcp(f"ERRR~008~'{hash_value}' does not match with hashed data")
                return 'Not Error'
            random_number = data.split(b'~')[-1]  # get random number
            data = data[:-(len(random_number) + 1)]  # remove random number

        data_len_str = str(len(encrypted_data)).zfill(8)

        #  print message properties
        if visible or ALL_MESSAGES_VISIBLE:
            print('\n******************************************')
            print('Receive length - ' + data_len_str)
            print(f'Hash Value - {hash_value.decode()}')
            print(f'Random number - {random_number.decode()}')
        try:
            if visible or ALL_MESSAGES_VISIBLE:
                print(f'data - {data[:1000].decode()}')
                print('******************************************\n')
            return data.decode()
        except (UnicodeDecodeError, AttributeError):
            if visible or ALL_MESSAGES_VISIBLE:
                print(b'data - ' + data[:1000])
                print('******************************************\n')
            return data

    def recv_udp(self, visible: bool = False) -> bytes or str:
        """
        Receiving message sent from server in UDP socket and decrypt it

        param visible: print the message parameters if True
        return: data sent from server in string or bytes
        """
        try:
            encrypted_data, addr = self.sock_udp.recvfrom(2916)
            if addr != (self.target_ip, self.udp_port):
                print(f'Error 015 : Message sent from unknown address')
                return 'Not Error'
        except socket.timeout:
            return 'Not Error'
        except socket.error:
            return 'Error'
        except ConnectionAbortedError:
            print('Error 005 : An existing connection was forcibly closed by the remote host')
            return 'Error'

        if encrypted_data == '' or encrypted_data == b'':
            print('Error 005 : An existing connection was forcibly closed by the remote host')
            return 'Error'
        return self.decrypt(encrypted_data, visible)

    def recv_by_size_tcp(self, visible: bool = False) -> bytes or str:
        """
        Receiving message sent from server in TCP socket by length field and decrypt it

        param visible: print the message parameters if True
        return: data sent from server in string or bytes
        """
        try:
            data_len_bytes = self.sock_tcp.recv(9)
            if 0 < len(data_len_bytes) < 9:
                print('Error 011 : Length field not big enough')
                return 'Not Error'
        except ConnectionAbortedError:
            print('Error 005 : An existing connection was forcibly closed by the remote host')
            return 'Error'
        except socket.timeout:
            return 'Not Error'
        except socket.error:
            return 'Error'

        if data_len_bytes == '' or data_len_bytes == b'':
            print('Error 005 : An existing connection was forcibly closed by the remote host')
            return 'Error'
        try:
            data_len = int(data_len_bytes[:-1])
            encrypted_data = self.sock_tcp.recv(data_len)
            if len(encrypted_data) != data_len:
                print('Error 012 : Length of message does not matching the length field')
                return 'Not Error'
        except ValueError:
            print('Error 007 : Length field is not int')
            self.send_with_size_tcp(f"ERRR~007~Length field is not int")
            return 'Not Error'

        return self.decrypt(encrypted_data, visible)

    def send_udp(self, data: bytes or str, visible: bool = False) -> None:
        """
        Sending message to server in UDP socket and encrypt it

        param data: data to send to server in string or bytes
        param visible: print the message parameters if True
        """
        encrypted_data = self.encrypt(data, visible)
        self.sock_udp.sendto(encrypted_data, (self.target_ip, self.udp_port))

    def send_with_size_tcp(self, data: bytes or str, visible: bool = False) -> None:
        """
        Sending message to server in TCP socket with length field and encrypt it

        param data: data to send to server in string or bytes
        param visible: print the message parameters if True
        """

        encrypted_data = self.encrypt(data, visible)
        message_length = str(len(encrypted_data)).zfill(8)
        self.sock_tcp.send(message_length.encode() + b'~' + encrypted_data)

    def handle_request(self, data: str or bytes) -> None:
        """
        Handle the request server sent
        data:  message sent from server
        """
        global online_users, text_channels, text_channel_messages, new_messages_num
        if data == 'Not Error':
            return
        if type(data) == str:
            fields = data.split('~')
        else:
            fields = data.split(b'~')
            fields[0] = fields[0].decode()
        if fields[0] == 'MSGS':
            text_channel_messages = []
            print(f'\ntext channel - {self.text_channel}: updated')
            for str_message in fields[1:]:
                text_channel_messages.append(str_message)
            new_messages_num += 1
        elif fields[0] == 'LOGS':
            self.logged_in = 'Y' == fields[1]
            if self.logged_in:
                self.operator = 'Y' == fields[2]
                self.muted = 'Y' == fields[3]
                self.deafened = 'Y' == fields[4]
        elif fields[0] == 'AUDS':
            audio_bytes = b'~'.join(fields[1:])
            if not self.deafened:
                stream.write(audio_bytes)
        elif fields[0] == 'ONLS':
            online_users = fields[1:]
        elif fields[0] == 'TCNS':
            text_channels = fields[1:]
            self.text_channel = text_channels[0]
            self.send_with_size_tcp(f'TXTC~{self.text_channel}')
            print('Got all text channels\'s names')
        elif fields[0] == 'ACNS':
            for audio_channel in fields[1:]:
                audio_channel_fields = audio_channel.split(';')
                if len(audio_channel_fields) > 1:
                    audio_channels[audio_channel_fields[0]] = audio_channel_fields[1:]
                else:
                    audio_channels[audio_channel_fields[0]] = []
            print('Got all audio channels\'s names')
        elif fields[0] == 'ERRR':
            print(f"Client Error {fields[1]} - {fields[2]}")
        else:
            print(f"Error 001 : '{fields[0]}' Message Type Couldn't be recognized")
            self.send_with_size_tcp(f"ERRR~001~'{fields[0]}' Message Type Couldn't be recognized")

    def send_audio(self):
        while not die:
            if self.audio_channel != '':
                if not self.muted and not self.deafened:
                    time.sleep(0.02)
                    audio_data = stream.read(CHUNK)
                    self.send_udp(b'AUDC~' + audio_data)

    def recv_audio(self):
        while not die:
            data = self.recv_udp()
            if data == 'Error':
                break
            elif data == 'Not Error':
                pass
            else:
                self.handle_request(data)

    def disconnect_from_server(self) -> None:
        """
        Ask from server for disconnection and disconnect
        """
        self.send_with_size_tcp(f'EXIT')
        print('Waiting For Disconnection Confirmation...')
        while True:
            data = self.recv_by_size_tcp()
            if data == 'EXTR' or data == 'Error':
                self.sock_tcp.close()
                self.sock_udp.close()
                print("Disconnected from Server")
                break


def login_system(client: Client) -> bool:
    """
    Login system

    param client: client
    return: if client logged in to user True else False
    """
    username = ''
    password = ''
    enter_username = False
    enter_password = False
    incorrect_inputs = False
    already_online = False
    username_already_taken = False
    screen = pygame.display.set_mode((600, 400))  # setting the screen sizes to (600, 400)

    while not client.logged_in:
        data = client.recv_by_size_tcp()
        if data == 'Error':
            return False
        client.handle_request(data)
        if client.logged_in:
            client.username = username
            return True
        elif data[:4] == 'LOGS':
            username = ''
            password = ''
            incorrect_inputs = data[5] == 'N'
            already_online = data[5] == 'A'
            username_already_taken = data[5] == 'S'

        screen.blit(login_screen, (0, 0))

        if incorrect_inputs:
            screen.blit(font_30.render('Username and Password not matching please try again', True,
                                       (200, 24, 39)), (20, 170))
        elif already_online:
            screen.blit(font_30.render('User already online please try again', True,
                                       (200, 24, 39)), (40, 170))
        elif username_already_taken:
            screen.blit(font_30.render('Username already taken please try again', True,
                                       (200, 24, 39)), (40, 170))
        while font_40.render(username, True, (0, 0, 0)).get_width() > 200:
            username = username[:-1]
        while font_40.render(password, True, (0, 0, 0)).get_width() > 200:
            password = password[:-1]

        if enter_password:
            pygame.draw.rect(screen, (204, 255, 255), pygame.Rect(226, 129, 209, 31))
        if enter_username:
            pygame.draw.rect(screen, (204, 255, 255), pygame.Rect(226, 85, 209, 32))
        screen.blit(font_40.render(username, True, (0, 0, 0)), (227, 87))
        screen.blit(font_40.render(password, True, (0, 0, 0)), (227, 130))

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                client.logged_in = True
                return False

            elif event.type == pygame.MOUSEBUTTONUP and event.button == 1:
                enter_password = False
                enter_username = False
                incorrect_inputs = False
                already_online = False
                username_already_taken = False
                x, y = pygame.mouse.get_pos()
                if 220 < x < 439 and 80 < y < 120:
                    enter_username = True

                elif 220 < x < 439 and 124 < y < 164:
                    enter_password = True

                elif 77 < x < 213 and 248 < y < 320:
                    client.send_with_size_tcp(f'LOGC~{username}~{password}')
                elif 248 < y < 320 and 364 < x < 499:
                    client.send_with_size_tcp(f'SGNC~{username}~{password}')

            elif event.type == pygame.KEYDOWN and (enter_password or enter_username):
                if event.key == pygame.K_BACKSPACE:
                    if enter_password and len(password) > 0:
                        password = password[:-1]
                    elif enter_username and len(username) > 0:
                        username = username[:-1]
                elif event.key == pygame.K_TAB:
                    if enter_password:
                        enter_username = True
                        enter_password = False
                    elif enter_username:
                        enter_username = False
                        enter_password = True
                elif event.key == pygame.K_KP_ENTER or event.key == pygame.K_RETURN:
                    if enter_username and password == '':
                        enter_password = True
                        enter_username = False
                    elif enter_password or enter_username:
                        enter_username = False
                        enter_password = False
                        client.send_with_size_tcp(f'LOGC~{username}~{password}')
                elif event.unicode.isalpha() or event.unicode.isnumeric() or event.unicode in SPECIAL_CHARACTERS:
                    if enter_password:
                        password += event.unicode
                    else:
                        username += event.unicode

        pygame.display.update()


def main() -> None:
    """
    Main Function
    """
    global display_width, display_height, die, new_messages_num
    client = None
    try:
        # setting client parameters and connecting to server
        client = Client()

        # setting screen defaulters
        audiotext_icon = pygame.transform.scale(pygame.image.load('client_assets\\AudioText-icon.png'), (35, 35))
        pygame.display.set_icon(audiotext_icon)
        pygame.display.set_caption('AudioText')

        while True:
            data = client.recv_by_size_tcp()
            fields = data.split('~')
            if fields[0] == 'PUBS':
                client.server_publicK = rsa.PublicKey.load_pkcs1(fields[1].encode())
                client.send_with_size_tcp(b'PRVC~'+symmetric_key)
                break
            elif fields[0] == 'WATS' or fields[0] == 'Error':
                client.sock_udp.close()
                client.sock_tcp.close()
                stream.stop_stream()
                stream.close()
                audio.terminate()
                print('Too many clients are connected to server or another Error happened')
                pygame.quit()
                time.sleep(4)  # wait before closing program
                sys.exit()
            else:
                print(f"Error 001 : '{fields[0]}' Message Type Couldn't be recognized")
                client.send_with_size_tcp(f"ERRR~001~'{fields[0]}' Message Type Couldn't be recognized")

        while True:
            data = client.recv_by_size_tcp()
            fields = data.split('~')
            if fields[0] == 'PORC':
                client.udp_port = int(fields[2])
                client.sock_udp.settimeout(0.02)
                client.sock_udp.bind(('0.0.0.0', int(fields[1])))
                break
            elif fields[0] == 'Error':
                die = True
                client.sock_udp.close()
                client.sock_tcp.close()
                stream.stop_stream()
                stream.close()
                audio.terminate()
                print('Too many clients are connected to server or another Error happened')
                pygame.quit()
                time.sleep(4)  # wait before closing program
                sys.exit()
            else:
                print(f"Error 001 : '{fields[0]}' Message Type Couldn't be recognized")
                client.send_with_size_tcp(f"ERRR~001~'{fields[0]}' Message Type Couldn't be recognized")

        client.sock_tcp.settimeout(0.02)
        # login system
        running = login_system(client)
        client.receiving_thread.start()
        client.sending_thread.start()

        # setting screen for main loop
        try:
            if running:
                screen = pygame.display.set_mode((display_width, display_height), pygame.RESIZABLE)
            else:
                screen = None  # No need in that line but make it with less possible problems
        except pygame.error:
            screen = None  # No need in that line but make it with less possible problems
            print('Screen can\'t be defined')
            running = False

        # default variables
        message = ''
        text_high = 10

        # main loop
        while running:
            # text channel messages screen
            pygame.draw.rect(screen, (38, 38, 38), pygame.Rect(300, 0, display_width - 540, display_height))
            # channels screen
            pygame.draw.rect(screen, (33, 33, 33), pygame.Rect(0, 0, 300, display_height - 100))
            # online users screen
            pygame.draw.rect(screen, (33, 33, 33), pygame.Rect(display_width - 240, 0, 240, display_height))
            # buttons screen
            pygame.draw.rect(screen, (21, 21, 21), pygame.Rect(0, display_height - 100, 300, 100))
            # username
            screen.blit(font_40.render(client.username, True, (170, 170, 170)), (5, display_height - 63))
            # message input
            pygame.draw.rect(screen, (50, 50, 53), pygame.Rect((321, display_height - 60), (display_width - 581, 40)))
            # channel's messages
            is_down = True
            for message_index in range(len(text_channel_messages)):  # text channel's messages
                list_message = text_channel_messages[message_index].split(';')
                # surface of message's sender username
                message_username = font_30.render(list_message[0], True, (255, 255, 255))
                # surface of message's date
                message_date = font_20.render(list_message[2], True, (255, 255, 255))
                # surface of message
                message_surface = font_30.render(list_message[1], True, (255, 255, 255))
                i = 1
                while message_surface.get_width() > display_width - 550:
                    message_surface = font_30.render(list_message[1][:-i], True, (255, 255, 255))
                    i += 1

                message_height = message_surface.get_height()
                message_username_height = message_username.get_height()
                place_in_screen = (10 + message_height + message_username_height) * message_index + text_high
                if place_in_screen + message_username_height > display_height - 65:
                    is_down = False
                    break
                screen.blit(message_username, (310, place_in_screen))
                screen.blit(message_date, (message_username.get_width() + 330, 2 + place_in_screen))
                if place_in_screen + message_username_height * 2 > display_height - 65:
                    is_down = False
                    break
                screen.blit(message_surface, (310, message_username_height + place_in_screen))

            for i in range(len(online_users)):  # online users
                online_user_surface = font_40.render(online_users[i], True, (170, 170, 170))
                if i * 40 + 20 + online_user_surface.get_height() > display_height:
                    break
                screen.blit(online_user_surface, (display_width - 220, i * 40 + 20))

            for i in range(len(text_channels)):  # text channels
                if client.text_channel == text_channels[i]:
                    text_channel_surface = font_30.render('T - ' + text_channels[i], True, (255, 255, 255))
                else:
                    text_channel_surface = font_30.render('T - ' + text_channels[i], True, (140, 140, 140))
                if (i + 1) * 40 > display_height - 100:  # i * 40 + 20 + high of text_channel_surface that equals to 20
                    break
                screen.blit(text_channel_surface, (10, i * 40 + 20))
                if new_messages_num > 0 and client.text_channel == text_channels[i]:
                    new_messages_num_surface = font_20.render(f'{new_messages_num}', True, (128, 0, 0))
                    screen.blit(new_messages_num_surface, (30 + text_channel_surface.get_width(), i * 40 + 25))

            audio_channel_index = 0
            place_of_audio_channel = len(text_channels) * 40 + 20
            for audio_channel in audio_channels.keys():  # audio channels
                if client.audio_channel == audio_channel:
                    audio_channel_surface = font_30.render('A - ' + audio_channel, True, (255, 255, 255))
                else:
                    audio_channel_surface = font_30.render('A - ' + audio_channel, True, (140, 140, 140))
                if display_height - 100 < place_of_audio_channel + 20:
                    break
                screen.blit(audio_channel_surface, (10, place_of_audio_channel))
                end_of_channel_screen = False
                active_people_num = 0
                for audio_channel_person in audio_channels[audio_channel]:
                    active_person_surface = font_30.render(audio_channel_person, True, (128, 128, 128))
                    end_of_channel_screen = place_of_audio_channel + (active_people_num + 2) * 30 > display_height - 100
                    if end_of_channel_screen:
                        break
                    screen.blit(active_person_surface, (30, place_of_audio_channel + active_people_num * 30 + 30))
                    active_people_num += 1
                if end_of_channel_screen:
                    break
                audio_channel_index += 1
                place_of_audio_channel += 40 + active_people_num * 30

            for i in range(len(message)):  # message entered
                message_surface = font_40.render(message[i:], True, (255, 255, 255))
                if message_surface.get_width() < display_width - 587:
                    screen.blit(message_surface, (325, display_height - 53))
                    break

            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False
                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_BACKSPACE and len(message) > 0:
                        message = message[:-1]
                    elif (event.key == pygame.K_KP_ENTER or event.key == pygame.K_RETURN) and message != '':
                        client.send_with_size_tcp(f'NMSC~{message}')
                        new_messages_num = -1
                        message = ''
                    else:
                        if event.unicode.isalpha() or event.unicode.isnumeric() or event.unicode in SPECIAL_CHARACTERS:
                            message += event.unicode
                elif event.type == pygame.VIDEORESIZE:
                    if screen.get_width() > MINIMUM_WIDTH:
                        display_width = screen.get_width()
                    else:
                        display_width = MINIMUM_WIDTH
                    if screen.get_height() > MINIMUM_HEIGHT:
                        display_height = screen.get_height()
                    else:
                        display_height = MINIMUM_HEIGHT

                    screen = pygame.display.set_mode((display_width, display_height), pygame.RESIZABLE)
                    print(f'Screen Resized to ({display_width} , {display_height})')
                elif event.type == pygame.MOUSEBUTTONUP:
                    if event.button == 1:
                        x, y = pygame.mouse.get_pos()
                        if y < display_height - 100 and x < 300:
                            text_high = 10
                            channel_num = int((y - 10) / 40)
                            if channel_num < len(text_channels) and client.text_channel != text_channels[channel_num]:
                                client.text_channel = text_channels[channel_num]
                                client.send_with_size_tcp(f'TXTC~{client.text_channel}')
                                new_messages_num = -1
                            else:
                                try:
                                    audio_channel_num = 0
                                    start_of_audio_channel = (0.5 + len(text_channels)) * 40
                                    while not start_of_audio_channel < y < start_of_audio_channel + 20:
                                        active_people_counter = len(list(audio_channels.values())[audio_channel_num])
                                        audio_channel_num += 1
                                        start_of_audio_channel += 40 + active_people_counter * 30
                                    if client.audio_channel != list(audio_channels.keys())[audio_channel_num]:
                                        last_audio_channel = client.audio_channel
                                        client.audio_channel = list(audio_channels.keys())[audio_channel_num]

                                        client.send_with_size_tcp(f'JONC~{client.audio_channel}~{last_audio_channel}')
                                    else:
                                        last_audio_channel = client.audio_channel
                                        client.audio_channel = ''
                                        client.send_with_size_tcp(f'JONC~~{last_audio_channel}')
                                except IndexError:
                                    pass  # pressed on nothing \ active person
                        elif 200 < x < 232 and display_height - 66 < y < display_height - 34:
                            if client.deafened:
                                client.deafened = False
                                client.send_with_size_tcp(f'DEFC~N')
                                print('Undeafened')
                                if client.muted:
                                    client.muted = False
                                    client.send_with_size_tcp(f'MUTC~N')
                                    print('Unmuted')
                                undeafen_sound.play()
                            else:
                                client.muted = not client.muted
                                if client.muted:
                                    client.send_with_size_tcp(f'MUTC~Y')
                                    print('Muted')
                                    mute_sound.play()
                                else:
                                    client.send_with_size_tcp(f'MUTC~N')
                                    print('Unmuted')
                                    unmute_sound.play()
                        elif 250 < x < 282 and display_height - 62 < y < display_height - 30:
                            client.deafened = not client.deafened
                            if client.deafened:
                                client.send_with_size_tcp(f'DEFC~Y')
                                print('Deafened')
                                deafen_sound.play()
                            else:
                                client.send_with_size_tcp(f'DEFC~N')
                                print('Undeafened')
                                undeafen_sound.play()
                    elif event.button == 5:
                        if not is_down:
                            text_high -= 10
                        elif new_messages_num > 0:
                            new_messages_num = 0
                    elif event.button == 4:
                        if text_high < 10:
                            text_high += 10
            if client.deafened:
                screen.blit(undeafen_icon, (250, display_height - 62))
            else:
                screen.blit(deafen_icon, (250, display_height - 62))
            if client.muted or client.deafened:
                screen.blit(unmute_icon, (200, display_height - 66))
            else:
                screen.blit(mute_icon, (200, display_height - 66))

            data = client.recv_by_size_tcp()
            if data == 'Error':
                break
            client.handle_request(data)

            pygame.display.update()

        die = True
        client.disconnect_from_server()
    except ConnectionResetError:
        print('Error 005 : An existing connection was forcibly closed by the remote host')
    except KeyboardInterrupt:
        print('Error 002 : Client program was forcibly closed')
    try:
        client.sending_thread.join()
        client.receiving_thread.join()
    except RuntimeError:
        pass
    try:
        client.sock_udp.close()
    except socket.error:
        pass
    try:
        client.sock_udp.close()
    except socket.error:
        pass
    except AttributeError:
        print('Client class did\'nt create new client')
    stream.stop_stream()
    stream.close()
    audio.terminate()
    pygame.quit()  # last line in main


if __name__ == '__main__':
    while True:
        try:
            testing = input('Do You Use One Computer?\nEnter (Y / N): ').upper()
        except KeyboardInterrupt:
            print('None\nError 002 : Client program was forcibly closed')
            pygame.quit()
            sys.exit()
        if testing == 'Y' or testing == 'N':
            break
        else:
            print()
    testing = testing == 'Y'
    main()
