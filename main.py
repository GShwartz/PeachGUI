import tkinter

from PIL import Image, ImageTk
from datetime import datetime
from termcolor import colored
from threading import Thread
from colorama import init
import os.path
import socket
import psutil
import time
import sys

# GUI
from tkinter import *
from tkinter import ttk
import tkinter as tk

# Local Modules
from Modules import screenshot
from Modules import tasks
from Modules import vital_signs
from Modules import sysinfo
from Modules import freestyle

init()
COLORS = ['snow', 'ghost white', 'white smoke', 'gainsboro', 'floral white', 'old lace',
          'linen', 'antique white', 'papaya whip', 'blanched almond', 'bisque', 'peach puff',
          'navajo white', 'lemon chiffon', 'mint cream', 'azure', 'alice blue', 'lavender',
          'lavender blush', 'misty rose', 'dark slate gray', 'dim gray', 'slate gray',
          'light slate gray', 'gray', 'light grey', 'midnight blue', 'navy', 'cornflower blue', 'dark slate blue',
          'slate blue', 'medium slate blue', 'light slate blue', 'medium blue', 'royal blue', 'blue',
          'dodger blue', 'deep sky blue', 'sky blue', 'light sky blue', 'steel blue', 'light steel blue',
          'light blue', 'powder blue', 'pale turquoise', 'dark turquoise', 'medium turquoise', 'turquoise',
          'cyan', 'light cyan', 'cadet blue', 'medium aquamarine', 'aquamarine', 'dark green', 'dark olive green',
          'dark sea green', 'sea green', 'medium sea green', 'light sea green', 'pale green', 'spring green',
          'lawn green', 'medium spring green', 'green yellow', 'lime green', 'yellow green',
          'forest green', 'olive drab', 'dark khaki', 'khaki', 'pale goldenrod', 'light goldenrod yellow',
          'light yellow', 'yellow', 'gold', 'light goldenrod', 'goldenrod', 'dark goldenrod', 'rosy brown',
          'indian red', 'saddle brown', 'sandy brown',
          'dark salmon', 'salmon', 'light salmon', 'orange', 'dark orange',
          'coral', 'light coral', 'tomato', 'orange red', 'red', 'hot pink', 'deep pink', 'pink', 'light pink',
          'pale violet red', 'maroon', 'medium violet red', 'violet red',
          'medium orchid', 'dark orchid', 'dark violet', 'blue violet', 'purple', 'medium purple',
          'thistle', 'snow2', 'snow3',
          'snow4', 'seashell2', 'seashell3', 'seashell4', 'AntiqueWhite1', 'AntiqueWhite2',
          'AntiqueWhite3', 'AntiqueWhite4', 'bisque2', 'bisque3', 'bisque4', 'PeachPuff2',
          'PeachPuff3', 'PeachPuff4', 'NavajoWhite2', 'NavajoWhite3', 'NavajoWhite4',
          'LemonChiffon2', 'LemonChiffon3', 'LemonChiffon4', 'cornsilk2', 'cornsilk3',
          'cornsilk4', 'ivory2', 'ivory3', 'ivory4', 'honeydew2', 'honeydew3', 'honeydew4',
          'LavenderBlush2', 'LavenderBlush3', 'LavenderBlush4', 'MistyRose2', 'MistyRose3',
          'MistyRose4', 'azure2', 'azure3', 'azure4', 'SlateBlue1', 'SlateBlue2', 'SlateBlue3',
          'SlateBlue4', 'RoyalBlue1', 'RoyalBlue2', 'RoyalBlue3', 'RoyalBlue4', 'blue2', 'blue4',
          'DodgerBlue2', 'DodgerBlue3', 'DodgerBlue4', 'SteelBlue1', 'SteelBlue2',
          'SteelBlue3', 'SteelBlue4', 'DeepSkyBlue2', 'DeepSkyBlue3', 'DeepSkyBlue4',
          'SkyBlue1', 'SkyBlue2', 'SkyBlue3', 'SkyBlue4', 'LightSkyBlue1', 'LightSkyBlue2',
          'LightSkyBlue3', 'LightSkyBlue4', 'SlateGray1', 'SlateGray2', 'SlateGray3',
          'SlateGray4', 'LightSteelBlue1', 'LightSteelBlue2', 'LightSteelBlue3',
          'LightSteelBlue4', 'LightBlue1', 'LightBlue2', 'LightBlue3', 'LightBlue4',
          'LightCyan2', 'LightCyan3', 'LightCyan4', 'PaleTurquoise1', 'PaleTurquoise2',
          'PaleTurquoise3', 'PaleTurquoise4', 'CadetBlue1', 'CadetBlue2', 'CadetBlue3',
          'CadetBlue4', 'turquoise1', 'turquoise2', 'turquoise3', 'turquoise4', 'cyan2', 'cyan3',
          'cyan4', 'DarkSlateGray1', 'DarkSlateGray2', 'DarkSlateGray3', 'DarkSlateGray4',
          'aquamarine2', 'aquamarine4', 'DarkSeaGreen1', 'DarkSeaGreen2', 'DarkSeaGreen3',
          'DarkSeaGreen4', 'SeaGreen1', 'SeaGreen2', 'SeaGreen3', 'PaleGreen1', 'PaleGreen2',
          'PaleGreen3', 'PaleGreen4', 'SpringGreen2', 'SpringGreen3', 'SpringGreen4',
          'green2', 'green3', 'green4', 'chartreuse2', 'chartreuse3', 'chartreuse4',
          'OliveDrab1', 'OliveDrab2', 'OliveDrab4', 'DarkOliveGreen1', 'DarkOliveGreen2',
          'DarkOliveGreen3', 'DarkOliveGreen4', 'khaki1', 'khaki2', 'khaki3', 'khaki4',
          'LightGoldenrod1', 'LightGoldenrod2', 'LightGoldenrod3', 'LightGoldenrod4',
          'LightYellow2', 'LightYellow3', 'LightYellow4', 'yellow2', 'yellow3', 'yellow4',
          'gold2', 'gold3', 'gold4', 'goldenrod1', 'goldenrod2', 'goldenrod3', 'goldenrod4',
          'DarkGoldenrod1', 'DarkGoldenrod2', 'DarkGoldenrod3', 'DarkGoldenrod4',
          'RosyBrown1', 'RosyBrown2', 'RosyBrown3', 'RosyBrown4', 'IndianRed1', 'IndianRed2',
          'IndianRed3', 'IndianRed4', 'sienna1', 'sienna2', 'sienna3', 'sienna4', 'burlywood1',
          'burlywood2', 'burlywood3', 'burlywood4', 'wheat1', 'wheat2', 'wheat3', 'wheat4', 'tan1',
          'tan2', 'tan4', 'chocolate1', 'chocolate2', 'chocolate3', 'firebrick1', 'firebrick2',
          'firebrick3', 'firebrick4', 'brown1', 'brown2', 'brown3', 'brown4', 'salmon1', 'salmon2',
          'salmon3', 'salmon4', 'LightSalmon2', 'LightSalmon3', 'LightSalmon4', 'orange2',
          'orange3', 'orange4', 'DarkOrange1', 'DarkOrange2', 'DarkOrange3', 'DarkOrange4',
          'coral1', 'coral2', 'coral3', 'coral4', 'tomato2', 'tomato3', 'tomato4', 'OrangeRed2',
          'OrangeRed3', 'OrangeRed4', 'red2', 'red3', 'red4', 'DeepPink2', 'DeepPink3', 'DeepPink4',
          'HotPink1', 'HotPink2', 'HotPink3', 'HotPink4', 'pink1', 'pink2', 'pink3', 'pink4',
          'LightPink1', 'LightPink2', 'LightPink3', 'LightPink4', 'PaleVioletRed1',
          'PaleVioletRed2', 'PaleVioletRed3', 'PaleVioletRed4', 'maroon1', 'maroon2',
          'maroon3', 'maroon4', 'VioletRed1', 'VioletRed2', 'VioletRed3', 'VioletRed4',
          'magenta2', 'magenta3', 'magenta4', 'orchid1', 'orchid2', 'orchid3', 'orchid4', 'plum1',
          'plum2', 'plum3', 'plum4', 'MediumOrchid1', 'MediumOrchid2', 'MediumOrchid3',
          'MediumOrchid4', 'DarkOrchid1', 'DarkOrchid2', 'DarkOrchid3', 'DarkOrchid4',
          'purple1', 'purple2', 'purple3', 'purple4', 'MediumPurple1', 'MediumPurple2',
          'MediumPurple3', 'MediumPurple4', 'thistle1', 'thistle2', 'thistle3', 'thistle4',
          'gray1', 'gray2', 'gray3', 'gray4', 'gray5', 'gray6', 'gray7', 'gray8', 'gray9', 'gray10',
          'gray11', 'gray12', 'gray13', 'gray14', 'gray15', 'gray16', 'gray17', 'gray18', 'gray19',
          'gray20', 'gray21', 'gray22', 'gray23', 'gray24', 'gray25', 'gray26', 'gray27', 'gray28',
          'gray29', 'gray30', 'gray31', 'gray32', 'gray33', 'gray34', 'gray35', 'gray36', 'gray37',
          'gray38', 'gray39', 'gray40', 'gray42', 'gray43', 'gray44', 'gray45', 'gray46', 'gray47',
          'gray48', 'gray49', 'gray50', 'gray51', 'gray52', 'gray53', 'gray54', 'gray55', 'gray56',
          'gray57', 'gray58', 'gray59', 'gray60', 'gray61', 'gray62', 'gray63', 'gray64', 'gray65',
          'gray66', 'gray67', 'gray68', 'gray69', 'gray70', 'gray71', 'gray72', 'gray73', 'gray74',
          'gray75', 'gray76', 'gray77', 'gray78', 'gray79', 'gray80', 'gray81', 'gray82', 'gray83',
          'gray84', 'gray85', 'gray86', 'gray87', 'gray88', 'gray89', 'gray90', 'gray91', 'gray92',
          'gray93', 'gray94', 'gray95', 'gray97', 'gray98', 'gray99']


class ColorChart(tk.Frame):
    MAX_ROWS = 36
    FONT_SIZE = 10

    def __init__(self, root):
        tk.Frame.__init__(self, root)
        r = 0
        c = 0

        for color in COLORS:
            label = tk.Label(self, text=color, bg=color,
                             font=("Times", self.FONT_SIZE, "bold"))
            label.grid(row=r, column=c, sticky="ew")
            r += 1

            if r > self.MAX_ROWS:
                r = 0
                c += 1

        self.pack(expand=1, fill="both")


class App(tk.Tk):
    clients = {}
    connections = {}
    connHistory = []
    ips = []
    targets = []

    # Temp dict to hold connected station's ID# & IP
    temp = {}

    port = 55400
    ttl = 5
    hostname = socket.gethostname()
    serverIP = str(socket.gethostbyname(hostname))
    path = r'c:\Peach'
    log_path = fr'{path}\server_log.txt'

    def __init__(self):
        super().__init__()
        # ======== Server Config ==========
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.serverIP, self.port))
        self.server.listen()

        # Create local app DIR
        if not os.path.exists(self.path):
            os.makedirs(self.path)

        # Run Listener Thread
        listenerThread = Thread(target=self.run, name="Listener Thread")
        listenerThread.daemon = True
        listenerThread.start()

        # ======== GUI Config ===========
        self.title("Peach")
        self.height = self.winfo_height()
        self.width = self.winfo_width()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # =-=-=-=-=-=-= FRAMES =-=-=-=-=-=-=-=
        # Main Window Frames
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar Frame
        self.sidebar_frame = Frame(self, width=150, background="RoyalBlue4")
        self.sidebar_frame.grid(row=0, column=0, sticky="nswe")
        self.sidebar_frame.rowconfigure(5, weight=10)

        # Main Frame
        self.main_frame = Frame(self, background="ghost white", relief="solid")
        self.main_frame.grid(row=0, column=1, sticky="nswe", padx=5)
        self.main_frame.rowconfigure(5, weight=1)

        # Main Frame top bar - shows server information
        self.main_frame_top = Frame(self.main_frame, relief='flat', height=30)
        self.main_frame_top.grid(row=0, column=1, sticky="nwes")

        # Main frame top bar LabelFrame
        self.top_bar_label = LabelFrame(self.main_frame, text="Server Information", relief='solid')
        self.top_bar_label.grid(row=0, column=1, sticky='news')

        # Main Frame Table space
        self.main_frame_table = Frame(self.main_frame, relief='flat')
        self.main_frame_table.grid(row=1, column=1, sticky="news", pady=5)

        # Controller Buttons LabelFrame
        self.controller_btns = LabelFrame(self.main_frame, text="Controller", relief='solid', height=50)
        self.controller_btns.grid(row=2, column=0, columnspan=2, sticky="ews", pady=5)

        # =-=-=-=-=-=-= BUTTONS =-=-=-=-=-=-=-=
        # Sidebar Buttons
        # Refresh Button
        self.refresh_bt = tk.Button(self.sidebar_frame,
                                    text="Refresh", width=15, pady=10,
                                    command=lambda: self.refresh())
        self.refresh_bt.grid(row=0, sticky="nwes")

        # Update Clients
        self.btn_update_clients = tk.Button(self.sidebar_frame,
                                            text="Update Clients", width=15, pady=10,
                                            command="")
        self.btn_update_clients.grid(row=2, sticky="nwes")

        # Create Connected Table inside Main Frame when show connected btn pressed
        self.table_frame = ttk.LabelFrame(self.main_frame_table, text="Connected Stations")
        self.table_frame.grid(row=0, sticky="new", pady=5)

        # Create a Table for connected stations
        self.table = ttk.Treeview(self.table_frame,
                                  columns=("id", "MAC Address",
                                           "IP Address", "Station Name",
                                           "Logged User", "Client Version"),
                                  show="headings", height=10, selectmode='browse')
        self.table.grid(row=0, pady=10)

        # Create Scrollbar
        self.table_sb = Scrollbar(self.table_frame, orient=VERTICAL)
        self.table_sb.grid(row=0, sticky="wns")

        # Columns & Headings config
        self.table.column("#1", anchor=CENTER)
        self.table.heading("#1", text="ID")
        self.table.column("#2", anchor=CENTER)
        self.table.heading("#2", text="MAC")
        self.table.column("#3", anchor=CENTER)
        self.table.heading("#3", text="IP")
        self.table.column("#4", anchor=CENTER)
        self.table.heading("#4", text="Station Name")
        self.table.column("#5", anchor=CENTER)
        self.table.heading("#5", text="Logged User")
        self.table.column("#6", anchor=CENTER)
        self.table.heading("#6", text="Client Version")
        self.table.bind("<Button 1>", self.selectItem)

        # Style Table
        self.style = ttk.Style()
        self.style.configure("Treeview", rowheight=20)
        self.style.map("Treeview")

        self.server_information()
        self.show_available_connections()

    # Refresh server info & connected stations table
    def refresh(self):
        self.server_information()
        self.show_available_connections()

    # ======== GUI Section =========
    # Display Server Information Thread
    def dsi_thread(self):
        # Display Server Information
        infoThread = Thread(target=self.server_information, name="ServerInfo")
        infoThread.daemon = True
        infoThread.start()

    # Close App Window
    def on_closing(self, event=0):
        self.destroy()

    # ======== Server Section =========
    def reset(self) -> None:
        self.__init__()
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.serverIp, self.serverPort))
        self.server.listen()

    def bytes_to_number(self, b: int) -> int:
        self.logIt_thread(self.log_path, msg=f'Running bytes_to_number({b})...')
        dt = get_date()
        res = 0
        for i in range(4):
            res += b[i] << (i * 8)
        return res

    def get_date(self) -> str:
        d = datetime.now().replace(microsecond=0)
        dt = str(d.strftime("%m/%d/%Y %H:%M:%S"))

        return dt

    def logIt(self, logfile=None, debug=None, msg='') -> bool:
        dt = self.get_date()
        if debug:
            print(f"{dt}: {msg}")

        if logfile is not None:
            try:
                if not os.path.exists(logfile):
                    with open(logfile, 'w') as lf:
                        lf.write(f"{dt}: {msg}\n")

                    return True

                else:
                    with open(logfile, 'a') as lf:
                        lf.write(f"{dt}: {msg}\n")

                    return True

            except FileExistsError:
                pass

    def logIt_thread(self, log_path=None, debug=False, msg='') -> None:
        self.logit_thread = Thread(target=self.logIt, args=(log_path, debug, msg), name="Log Thread")
        self.logit_thread.start()

    def run(self) -> None:
        self.logIt_thread(self.log_path, msg=f'Running run()...')
        self.logIt_thread(self.log_path, msg=f'Calling connect() in new thread...')
        self.connectThread = Thread(target=self.connect, daemon=True, name=f"Connect Thread")
        self.connectThread.start()

        self.logIt_thread(self.log_path, msg=f'Adding thread to threads list...')
        self.logIt_thread(self.log_path, msg=f'Thread added to threads list.')

    def connect(self) -> None:
        def get_mac_address() -> str:
            self.logIt_thread(self.log_path, msg=f'Waiting for MAC address from {self.ip}...')
            self.mac = self.conn.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'MAC Address: {self.mac}')

            self.logIt_thread(self.log_path, msg=f'Sending confirmation to {self.ip}...')
            self.conn.send('OK'.encode())
            self.logIt_thread(self.log_path, msg=f'Send completed.')

            return self.mac

        def get_hostname() -> str:
            self.logIt_thread(self.log_path, msg=f'Waiting for remote station name...')
            self.ident = self.conn.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Remote station name: {self.ident}')

            self.logIt_thread(self.log_path, msg=f'Sending Confirmation to {self.ip}...')
            self.conn.send('OK'.encode())
            self.logIt_thread(self.log_path, msg=f'Send completed.')

            return self.ident

        def get_user() -> str:
            self.logIt_thread(self.log_path, msg=f'Waiting for remote station current logged user...')
            self.user = self.conn.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Remote station user: {self.user}')

            self.logIt_thread(self.log_path, msg=f'Sending Confirmation to {self.ip}...')
            self.conn.send('OK'.encode())
            self.logIt_thread(self.log_path, msg=f'Send completed.')

            return self.user

        def get_client_version() -> str:
            self.logIt_thread(self.log_path, msg=f'Waiting for client version...')
            self.client_version = self.conn.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Client version: {self.client_version}')

            self.logIt_thread(self.log_path, msg=f'Sending confirmation to {self.ip}...')
            self.conn.send('OK'.encode())
            self.logIt_thread(self.log_path, msg=f'Send completed.')

            return self.client_version

        self.logIt_thread(self.log_path, msg=f'Running connect()...')
        while True:
            self.logIt_thread(self.log_path, msg=f'Accepting connections...')
            self.conn, (self.ip, self.port) = self.server.accept()
            self.logIt_thread(self.log_path, msg=f'Connection from {self.ip} accepted.')

            try:
                # Get MAC Address
                self.client_mac = get_mac_address()

                # Get Remote Computer's Name
                get_hostname()

                # Get Current User
                get_user()

                # Get Client Version
                get_client_version()

            except (WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
                return  # Restart The Loop

            # Update Thread Dict and Connection Lists
            if self.conn not in self.targets and self.ip not in self.ips:
                self.logIt_thread(self.log_path, msg=f'New Connection!')

                # Add Socket Connection To Targets list
                self.logIt_thread(self.log_path, msg=f'Adding {self.conn} to targets list...')
                self.targets.append(self.conn)
                self.logIt_thread(self.log_path, msg=f'targets list updated.')

                # Add IP Address Connection To IPs list
                self.logIt_thread(self.log_path, msg=f'Adding {self.ip} to ips list...')
                self.ips.append(self.ip)
                self.logIt_thread(self.log_path, msg=f'ips list updated.')

                # Set Temp Dict To Update Live Connections List
                self.logIt_thread(self.log_path, msg=f'Adding {self.conn} | {self.ip} to temp live connections dict...')
                self.temp_connection = {self.conn: self.ip}
                self.logIt_thread(self.log_path, msg=f'Temp connections dict updated.')

                # Add Temp Dict To Connections List
                self.logIt_thread(self.log_path, msg=f'Updating connections list...')
                self.connections.update(self.temp_connection)
                self.logIt_thread(self.log_path, msg=f'Connections list updated.')

                # Set Temp Idents Dict For Idents
                self.logIt_thread(self.log_path, msg=f'Creating dict to hold ident details...')
                self.temp_ident = {self.conn: {
                    self.client_mac: {
                        self.ip: {
                            self.ident: {
                                self.user: self.client_version}}}}}

                self.logIt_thread(self.log_path, msg=f'Dict created: {self.temp_ident}')

                # Add Temp Idents Dict To Idents Dict
                self.logIt_thread(self.log_path, msg=f'Updating live clients list...')
                self.clients.update(self.temp_ident)
                self.logIt_thread(self.log_path, msg=f'Live clients list updated.')

            # Create a Dict of Connection, IP, Computer Name, Date & Time
            self.logIt_thread(self.log_path, msg=f'Fetching current date & time...')
            dt = get_date()
            self.logIt_thread(self.log_path, msg=f'Creating a connection dict...')
            self.temp_connection_record = {self.conn: {self.ip: {self.ident: {self.user: dt}}}}
            self.logIt_thread(self.log_path, msg=f'Connection dict created: {self.temp_connection_record}')

            # Add Connection to Connection History
            self.logIt_thread(self.log_path, msg=f'Adding connection to connection history...')
            self.connHistory.append(self.temp_connection_record)
            self.logIt_thread(self.log_path, msg=f'Connection added to connection history.')

            self.logIt_thread(self.log_path, msg=f'Calling self.welcome_message() condition...')
            if self.welcome_message():
                continue

    def welcome_message(self) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running welcome_message()...')

        # Send Welcome Message
        try:
            self.welcome = "Connection Established!"
            self.logIt_thread(self.log_path, msg=f'Sending welcome message...')
            self.conn.send(f"@Server: {self.welcome}".encode())
            self.logIt_thread(self.log_path, msg=f'{self.welcome} sent to {self.ident}.')

            return True

        except (WindowsError, socket.error) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
            if self.conn in self.targets and self.ip in self.ips:
                self.logIt_thread(self.log_path, msg=f'Removing {self.conn} from self.targets...')
                self.targets.remove(self.conn)

                self.logIt_thread(self.log_path, msg=f'Removing {self.ip} from self.ips list...')
                self.ips.remove(self.ip)

                self.logIt_thread(self.log_path, msg=f'Deleting {self.conn} from self.connections.')
                del self.connections[self.conn]

                self.logIt_thread(self.log_path, msg=f'Deleting {self.conn} from self.clients...')
                del self.clients[self.conn]

                self.logIt_thread(self.log_path, msg=f'[V]Connection removed from lists.')

                return False

    def connection_history(self) -> None:
        self.logIt_thread(self.log_path, msg=f'Running connection_history()...')
        print("\t\t" + f"{colored('=', 'blue')}" * 20, f"=> {colored('CONNECTION HISTORY', 'red')} <=",
              f"{colored('=', 'blue')}" * 20)
        c = 1  # Initiate Counter for Connection Number
        try:
            # Iterate Through Connection History List Items
            self.logIt_thread(self.log_path, msg=f'Iterating self.connHistory...')
            for connection in self.connHistory:
                for conKey, ipValue in connection.items():
                    for ipKey, identValue in ipValue.items():
                        for identKey, userValue in identValue.items():
                            for userKey, timeValue in userValue.items():
                                print(
                                    f"[{colored(str(c), 'green')}]{colored('IP', 'cyan')}: {ipKey} | "
                                    f"{colored('Station Name', 'cyan')}: {identKey} | "
                                    f"{colored('User', 'cyan')}: {userKey} | "
                                    f"{colored('Time', 'cyan')}: {str(timeValue).replace('|', ':')}")
                    c += 1

        # Break If Client Lost Connection
        except (KeyError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, msg=f'Iteration Error: {e}')
            return

    def vital_signs(self) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running vital_signs()...')

        self.logIt_thread(self.log_path,
                          msg=f'Init class: vitals({self.targets, self.ips, self.clients, self.connections, self.log_path})...')
        vitals = vital_signs.Vitals(self.targets, self.ips, self.clients,
                                    self.connections, self.log_path, self.ident)
        if vitals.vitals_input():
            vitals.vital_signs()
            return True

        else:
            self.logIt_thread(self.log_path, msg=f'Closing vital_signs()...')
            return False

    def sac_thread(self):
        self.sacThread = Thread(target=self.show_available_connections,
                                name="Show Available Connections Thread")
        self.sacThread.daemon = True
        self.sacThread.start()

    def selectItem(self, event):
        rowid = self.table.identify_row(event.y)
        row = self.table.item(rowid)['values']
        print(f"row: {row}")
        try:
            if not row[2] in self.temp.values():
                self.temp[row[0]] = row[2]

        except IndexError:
            pass

        finally:
            print(self.temp)

        # Create a Controller Box
        for id, ip in self.temp.items():
            for clientConn, clientValues in self.clients.items():
                # print(f"id: {id} ip: {ip} | clientConn: {clientConn} clientIP: {clientValues}")
                for clientMac, clientIPv in clientValues.items():
                    for clientIP, vals in clientIPv.items():
                        if clientIP == ip:
                            self.screenshot_btn = Button(self.controller_btns, text="Screenshot", width=15, pady=5,
                                                         command=lambda: self.screenshot(clientConn, ip))

                            self.screenshot_btn.grid(row=0, sticky="w", pady=5)

                            shellThread = Thread(target=self.shell, args=(clientConn, clientIP), name="Shell Thread")
                            shellThread.daemon = True
                            shellThread.start()
                            self.temp.clear()

                            return

    def show_available_connections(self) -> None:
        if len(self.ips) == 0 and len(self.targets) == 0:
            self.logIt_thread(self.log_path, msg=f'No connected Stations')
            print(f"[{colored('*', 'cyan')}]No connected stations.\n")

        self.logIt_thread(self.log_path, msg=f'Running show_available_connections()...')

        def make_tmp():
            count = 0
            for conKey, macValue in self.clients.items():
                # print(f"Mac Value: {macValue}")
                for macKey, ipValue in macValue.items():
                    # print(f"MAC: {macKey}, IP: {ipValue}")
                    for ipKey, identValue in ipValue.items():
                        # print(f"ipKey: {ipKey}, identValue: {identValue}")
                        for con, ip in self.connections.items():
                            # print(f"con: {con}, ip: {ip}")
                            if ip == ipKey:
                                for identKey, userValue in identValue.items():
                                    # print(f"identKey: {identKey}, userValue: {userValue}")
                                    for userV, clientVer in userValue.items():
                                        # print(f"userV: {userV}, clientVer: {clientVer}")
                                        if (count, macKey, ipKey, identKey, userValue) in self.tmp_availables:
                                            continue

                                self.tmp_availables.append((count, macKey, ipKey, identKey, userV, clientVer))
                count += 1

            self.logIt_thread(self.log_path, msg=f'Available list created.')

        def extract():
            for item in self.tmp_availables:
                for conKey, ipValue in self.clients.items():
                    for ipKey in ipValue.keys():
                        if item[1] == ipKey:
                            session = item[0]
                            stationMAC = item[1]
                            stationIP = item[2]
                            stationName = item[3]
                            loggedUser = item[4]
                            clientVersion = item[5]

                            # Show results in GUI table
                            self.table.insert('', 'end', values=(session, stationMAC, stationIP,
                                                                 stationName, loggedUser, clientVersion))

                            print(f"Session [{colored(f'{session}', 'cyan')}] | "
                                  f"Station MAC: {colored(f'{stationMAC}', 'green')} | "
                                  f"Station IP: {colored(f'{stationIP}', 'green')} | "
                                  f"Station Name: {colored(f'{stationName}', 'green')} | "
                                  f"Logged User: {colored(f'{loggedUser}', 'green')} | "
                                  f"Client Version: {colored(clientVersion, 'green')}")

            self.logIt_thread(self.log_path, msg=f'Extraction completed.')

        # Cleaning availables list
        self.logIt_thread(self.log_path, msg=f'Cleaning availables list...')
        self.tmp_availables = []

        # Clear previous entries in GUI table
        self.table.delete(*self.table.get_children())

        print(f"[{colored('*', 'cyan')}] {colored('Available Connections', 'green')} [{colored('*', 'cyan')}]")
        print(f"{colored('=', 'yellow') * 29}")

        self.logIt_thread(self.log_path, msg=f'Creating available list...')
        make_tmp()

        self.logIt_thread(self.log_path,
                          msg=f'Extracting: Session | Station IP | Station Name | Logged User '
                              f'from clients list...')
        extract()

    def get_station_number(self) -> (int, int, int):
        self.logIt_thread(self.log_path, msg=f'Running get_station_number()...')
        if len(self.tmp_availables) == 0:
            self.logIt_thread(self.log_path, msg=f'No available connections.')
            print(f"[{colored('*', 'cyan')}]No available connections.\n")
            return

        tries = 1
        while True:
            self.logIt_thread(self.log_path, msg=f'Waiting for station number...')
            station_num = input(f"\n@Session #>> ")
            self.logIt_thread(self.log_path, msg=f'Station number: {station_num}')
            if str(station_num).lower() == 'q':
                self.logIt_thread(self.log_path, msg=f'Station number: {station_num} | moving back...')
                return False

            try:
                self.logIt_thread(self.log_path, msg=f'Running input validation on {station_num}')
                val = int(station_num)
                if int(station_num) <= 0 or int(station_num) <= (len(self.tmp_availables)):
                    tarnum = self.targets[int(station_num)]
                    ipnum = self.ips[int(station_num)]
                    self.logIt_thread(log_path, msg=f'=== End of get_station_number() ===')
                    return int(station_num), tarnum, ipnum

                else:
                    self.logIt_thread(log_path, msg=f'Wrong input detected.')
                    print(f"[{colored('*', 'red')}]Wrong Number. Choose between [1 - {len(self.tmp_availables)}].\n"
                          f"[Try {colored(f'{tries}', 'yellow')}/{colored('3', 'yellow')}]")

            except (TypeError, ValueError, IndexError):
                self.logIt_thread(self.log_path, msg=f'Wrong input detected.')
                print(f"[{colored('*', 'red')}]Numbers only. Choose between [1 - {len(self.tmp_availables)}].\n"
                      f"[Try {colored(f'{tries}', 'yellow')}/{colored('3', 'yellow')}]")

    def show_shell_commands(self, ip: str) -> None:
        self.logIt_thread(self.log_path, msg=f'Running show_shell_commands()...')
        self.logIt_thread(self.log_path, msg=f'Displaying headline...')
        print("\t\t" + f"{colored('=', 'blue')}" * 20, f"=> {colored('REMOTE CONTROL', 'red')} <=",
              f"{colored('=', 'blue')}" * 20)

        self.logIt_thread(self.log_path, msg=f'Displaying Station IP | Station Name | Logged User in headline...')
        for conKey, ipValue in self.clients.items():
            for ipKey, userValue in ipValue.items():
                if ipKey == ip:
                    for item in self.tmp_availables:
                        if item[1] == ip:
                            for identKey, timeValue in userValue.items():
                                loggedUser = item[3]
                                clientVersion = item[4]
                                print("\t" + f"IP: {colored(f'{ipKey}', 'green')} | "
                                             f"Station Name: {colored(f'{identKey}', 'green')} | "
                                             f"Logged User: {colored(f'{loggedUser}', 'green')} | "
                                             f"Client Version: {colored(clientVersion, 'green')}")

        print("\t\t" + f"{colored('=', 'yellow')}" * 62 + "\n")

        self.logIt_thread(self.log_path, msg=f'Displaying shell commands menu...')
        print(f"\t\t[{colored('1', 'cyan')}]Screenshot          \t\t---------------> "
              f"Capture screenshot.")
        print(f"\t\t[{colored('2', 'cyan')}]System Info         \t\t---------------> "
              f"Show Station's System Information")
        print(f"\t\t[{colored('3', 'cyan')}]Last Restart Time   \t\t---------------> "
              f"Show remote station's last restart time")
        print(f"\t\t[{colored('4', 'cyan')}]Anydesk             \t\t---------------> "
              f"Start Anydesk")
        print(f"\t\t[{colored('5', 'cyan')}]Tasks               \t\t---------------> "
              f"Show remote station's running tasks")
        print(f"\t\t[{colored('6', 'cyan')}]Restart             \t\t---------------> "
              f"Restart remote station")
        print(f"\t\t[{colored('7', 'cyan')}]CLS                 \t\t---------------> "
              f"Clear Screen")
        print(f"\n\t\t[{colored('8', 'red')}]Back                \t\t---------------> "
              f"Back to Control Center \n")

        self.logIt_thread(self.log_path, msg=f'=== End of show_shell_commands() ===')

    def restart(self, con: str, ip: str) -> bool:
        def confirm_restart(con) -> bool:
            self.logIt_thread(self.log_path, msg=f'Running confirm_restart()...')
            tries = 0
            while True:
                try:
                    self.logIt_thread(self.log_path, msg=f'Running input validation on {self.sure}...')
                    str(self.sure)

                except TypeError:
                    self.logIt_thread(self.log_path, msg=f'Wrong input detected.')
                    print(f"[{colored('*', 'red')}]Wrong Input. [({colored('Y/y', 'yellow')}) | "
                          f"({colored('N/n', 'yellow')})]")

                    if tries == 3:
                        self.logIt_thread(self.log_path, msg=f'Tries: 3')
                        print("U obviously don't know what you're doing. goodbye.")
                        if len(server.targets) > 0:
                            self.logIt_thread(self.log_path, msg=f'Closing live connections...')
                            for t in server.targets:
                                t.send('exit'.encode())
                                t.shutdown(socket.SHUT_RDWR)
                                t.close()

                            self.logIt_thread(self.log_path, msg=f'Live connections closed.')

                        self.logIt_thread(self.log_path, msg=f'Exiting app with code 1...')
                        sys.exit(1)

                    tries += 1

                if str(self.sure).lower() == "y":
                    self.logIt_thread(self.log_path, msg=f'User input: {self.sure} | Returning TRUE...')
                    return True

                elif str(self.sure).lower() == "n":
                    self.logIt_thread(self.log_path, msg=f'User input: {self.sure} | Returning FALSE...')
                    con.send('n'.encode())
                    break

                else:
                    self.logIt_thread(self.log_path, msg=f'Wrong input detected.')
                    print(f"[{colored('*', 'red')}]Wrong Input. [({colored('Y/y', 'yellow')}) | "
                          f"({colored('N/n', 'yellow')})]")

                    if tries == 3:
                        self.logIt_thread(self.log_path, msg=f'Tries: 3')
                        print("U obviously don't know what you're doing. goodbye.")
                        if len(server.targets) > 0:
                            self.logIt_thread(self.log_path, msg=f'Closing live connections...')
                            dt = get_date()
                            for t in server.targets:
                                t.send('exit'.encode())
                                t.shutdown(socket.SHUT_RDWR)
                                t.close()

                            self.logIt_thread(self.log_path, msg=f'Live connections closed.')

                        self.logIt_thread(self.log_path, msg=f'Exiting app with code 1...')
                        sys.exit(1)

                    tries += 1

        self.logIt_thread(self.log_path, msg=f'Running restart({con}, {ip})...')
        errCount = 3
        self.sure = input("Are you sure you want to restart [Y/n]?")
        if confirm_restart(con):
            try:
                self.logIt_thread(self.log_path, msg=f'Sending restart command to client...')
                con.send('restart'.encode())
                try:
                    self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                    self.remove_lost_connection(con, ip)
                    return True

                except RuntimeError as e:
                    self.logIt_thread(self.log_path, msg=f'Runtime Error: {e}')
                    return False

            except (WindowsError, socket.error) as e:
                self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
                print(f"[{colored('!', 'red')}]Client lost connection.")

                self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return False

        else:
            return False

    def anydesk(self, con: str, ip: str) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running anydesk({con}, {ip})...')
        try:
            self.logIt_thread(self.log_path, msg=f'Sending anydesk command to {con}...')
            con.send('anydesk'.encode())
            self.logIt_thread(self.log_path, msg=f'Send Completed.')

            self.logIt_thread(self.log_path, msg=f'Waiting for response from client...')
            msg = con.recv(1024).decode()
            self.logIt_thread(self.log_path, msg=f'Client response: {msg}.')

            if "OK" not in msg:
                self.logIt_thread(self.log_path, msg=f'Printing msg from client...')
                print(msg)
                while True:
                    try:
                        install_input = str(input("Install Anydesk [Y/n]? "))

                    except ValueError:
                        print(f"[{colored('!', 'red')}]Wrong input.")
                        continue

                    if str(install_input).lower() == "y":
                        print("Installing anydesk...")
                        self.logIt_thread(self.log_path, msg=f'Sending install command to {con}...')
                        con.send('y'.encode())
                        self.logIt_thread(self.log_path, msg=f'Send Completed.')

                        while True:
                            self.logIt_thread(self.log_path, msg=f'Waiting for response from client...')
                            msg = con.recv(1024).decode()
                            self.logIt_thread(self.log_path, msg=f'Client response: {msg}.')

                            if "OK" not in str(msg):
                                print(msg)
                                continue

                            else:
                                print(msg)
                                return False

                        return True

                    elif str(install_input).lower() == "n":
                        self.logIt_thread(self.log_path, msg=f'Sending cancel command to {con}...')
                        con.send('n'.encode())
                        self.logIt_thread(self.log_path, msg=f'Send Completed.')
                        break

                    else:
                        continue

        except (WindowsError, ConnectionError, socket.error) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}.')
            print(f"[{colored('!', 'red')}]Client lost connection.")
            try:
                self.logIt_thread(self.log_path, debug=True,
                                  msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                self.remove_lost_connection(con, ip)
                return False

            except RuntimeError as e:
                self.logIt_thread(self.log_path, debug=True, msg=f'Runtime Error: {e}.')
                return False

    def screenshot(self, con: str, ip: str) -> None:
        try:
            print(f"[{colored('*', 'cyan')}]Fetching screenshot...")
            self.logIt_thread(self.log_path, msg=f'Sending screen command to client...')
            con.send('screen'.encode())
            self.logIt_thread(self.log_path, msg=f'Send Completed.')

            self.logIt_thread(self.log_path, msg=f'Calling Module: '
                                                 f'screenshot({con, self.path, self.tmp_availables, self.clients})...')

            scrnshot = screenshot.Screenshot(con, self.path, self.tmp_availables,
                                             self.clients, self.log_path, self.targets)

            self.logIt_thread(self.log_path, msg=f'Calling screenshot.recv_file()...')
            scrnshot.recv_file(ip)

        except (WindowsError, socket.error, ConnectionResetError) as e:
            self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
            print(f"[{colored('!', 'red')}]Client lost connection.")

            self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip}...)')
            self.remove_lost_connection(con, ip)

    def shell(self, con: str, ip: str) -> None:
        self.logIt_thread(self.log_path, msg=f'Running shell({con}, {ip})...')
        errCount = 0
        while True:
            self.logIt_thread(self.log_path, msg=f'Calling self.show_shell_commands({ip})...')
            self.show_shell_commands(ip)

            # Wait for User Input
            self.logIt_thread(self.log_path, msg=f'Waiting for user input...')
            cmd = input(f"COMMAND@{ip}> ")

            # Input Validation
            try:
                self.logIt_thread(self.log_path, msg=f'Performing input validation on user input: {cmd}...')
                val = int(cmd)

            except (TypeError, ValueError):
                self.logIt_thread(self.log_path, msg=f'Wrong input detected.')
                print(f"[{colored('*', 'red')}]Numbers Only [{colored('1', 'yellow')} - {colored('8', 'yellow')}]!")
                continue

            # Run Custom Command
            if int(cmd) == 100:
                self.logIt_thread(self.log_path, msg=f'Command: 100')
                try:
                    self.logIt_thread(self.log_path, msg=f'Send freestyle command...')
                    con.send("freestyle".encode())
                    self.logIt_thread(self.log_path, msg=f'Send Completed.')

                except (WindowsError, socket.error) as e:
                    self.logIt_thread(self.log_path, msg=f'Connection Error: {e}')
                    break

                for item, connection in zip(self.tmp_availables, self.connections):
                    for conKey, ipValue in self.clients.items():
                        if conKey == connection:
                            for ipKey in ipValue.keys():
                                if item[1] == ipKey:
                                    ipval = item[1]
                                    host = item[2]
                                    user = item[3]

                self.logIt_thread(self.log_path, msg=f'Initializing Freestyle Module...')
                free = freestyle.Freestyle(con, path, self.tmp_availables, self.clients,
                                           log_path, host, user)

                self.logIt_thread(self.log_path, msg=f'Calling freestyle module...')
                free.freestyle(ip)

                continue

            # Create INT Zone Condition
            self.logIt_thread(self.log_path, msg=f'Creating user input zone from 1-8...')
            if int(cmd) <= 0 or int(cmd) > 8:
                errCount += 1
                if errCount == 3:
                    self.logIt_thread(self.log_path, msg=f'Tries: 3')
                    print("U obviously don't know what you're doing. goodbye.")

                    self.logIt_thread(self.log_path, msg=f'Sending exit command to {ip}...')
                    con.send("exit".encode())
                    self.logIt_thread(self.log_path, msg=f'Send Completed.')

                    self.logIt_thread(self.log_path, msg=f'Closing connections...')
                    con.close()
                    self.logIt_thread(self.log_path, msg=f'Connections closed.')

                    self.logIt_thread(self.log_path, msg=f'Exiting app with code 1...')
                    sys.exit(1)

                self.logIt_thread(self.log_path, msg=f'Wrong input detected.')
                print(f"[{colored('*', 'red')}]{cmd} not in the menu."
                      f"[try {colored(errCount, 'yellow')} of {colored('3', 'yellow')}]\n")

            # Screenshot
            if int(cmd) == 1:
                self.screenshot(con, ip)

            # System Information
            elif int(cmd) == 2:
                self.logIt_thread(self.log_path, msg=f'Running system information condition...')
                errCount = 0
                if len(self.targets) == 0:
                    self.logIt_thread(self.log_path, msg=f'No available connections.')
                    print(f"[{colored('*', 'red')}]No connected stations.")
                    break

                try:
                    self.logIt_thread(self.log_path, msg=f'Initializing Module: sysinfo...')
                    sinfo = sysinfo.Sysinfo(con, self.ttl, path, self.tmp_availables, self.clients, self.log_path)

                    print(f"[{colored('*', 'cyan')}]Fetching system information, please wait... ")
                    self.logIt_thread(self.log_path, msg=f'Calling sysinfo.run()...')
                    if sinfo.run(ip):
                        print(f"[{colored('V', 'green')}]OK!")

                except (WindowsError, socket.error, ConnectionResetError) as e:
                    self.logIt_thread(self.log_path, debug=True, msg=f'Connection Error: {e}.')
                    # print(f"[{colored('!', 'red')}]Client lost connection.")
                    try:
                        self.logIt_thread(self.log_path, msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                        self.remove_lost_connection(con, ip)
                        return

                    except RuntimeError:
                        return

            # Last Restart Time
            elif int(cmd) == 3:
                self.logIt_thread(self.log_path, debug=False, msg=f'Running last restart condition...')
                errCount = 0
                if len(self.targets) == 0:
                    self.logIt_thread(self.log_path, debug=False, msg=f'No available connections.')
                    print(f"[{colored('*', 'red')}]No connected stations.")
                    break

                try:
                    self.logIt_thread(self.log_path, debug=False, msg=f'Sending lr command to client...')
                    con.send('lr'.encode())
                    self.logIt_thread(self.log_path, debug=False, msg=f'Send Completed.')

                    self.logIt_thread(self.log_path, debug=False, msg=f'Waiting for response from client...')
                    msg = con.recv(4096).decode()
                    self.logIt_thread(self.log_path, debug=False, msg=f'Client response: {msg}')
                    print(f"[{colored('@', 'green')}]{msg}")

                except (WindowsError, socket.error, ConnectionResetError) as e:
                    self.logIt_thread(self.log_path, debug=False, msg=f'Connection Error: {e}.')
                    print(f"[{colored('!', 'red')}]Client lost connection.")
                    try:
                        self.logIt_thread(self.log_path, debug=False,
                                          msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                        self.remove_lost_connection(con, ip)
                        break

                    except RuntimeError as e:
                        self.logIt_thread(self.log_path, debug=True, msg=f'Runtime Error: {e}.')
                        return

            # Anydesk
            elif int(cmd) == 4:
                self.logIt_thread(self.log_path, msg=f'Running anydesk condition...')
                errCount = 0
                print(f"[{colored('*', 'magenta')}]Starting AnyDesk...\n")
                self.logIt_thread(self.log_path, msg=f'Calling self.anydesk({con}, {ip})...')
                self.anydesk(con, ip)

            # Tasks
            elif int(cmd) == 5:
                self.logIt_thread(self.log_path, debug=False, msg=f'Running tasks condition...')
                errCount = 0
                if len(self.targets) == 0:
                    self.logIt_thread(self.log_path, debug=False, msg=f'No available connections.')
                    print(f"[{colored('*', 'red')}]No connected stations.")
                    break

                self.logIt_thread(self.log_path, debug=False, msg=f'Initializing Module: tasks...')
                tsks = tasks.Tasks(con, ip, ttl, self.clients, self.connections,
                                   self.targets, self.ips, self.tmp_availables, path, self.log_path)

                self.logIt_thread(self.log_path, debug=False, msg=f'Calling tasks.tasks()...')
                if not tsks.tasks(ip):
                    return False

                self.logIt_thread(self.log_path, debug=False, msg=f'Calling tasks.kill_tasks()...')
                task = tsks.kill_tasks(ip)
                if task is None:
                    continue

                try:
                    self.logIt_thread(self.log_path, debug=False, msg=f'Calling tasks.task_to_kill()...')
                    tasks.task_to_kill(ip)
                    return True

                except (WindowsError, socket.error, ConnectionResetError, ConnectionError) as e:
                    self.logIt_thread(self.log_path, debug=False, msg=f'Connection Error: {e}')
                    print(f"[{colored('!', 'red')}]Client lost connection.")
                    try:
                        self.logIt_thread(self.log_path, debug=False,
                                          msg=f'Calling self.remove_lost_connection({con}, {ip})...')
                        self.remove_lost_connection(con, ip)

                    except RuntimeError as e:
                        self.logIt_thread(self.log_path, debug=False, msg=f'Runtime Error: {e}.')
                        return False

            # Restart
            elif int(cmd) == 6:
                self.logIt_thread(self.log_path, debug=False, msg=f'Running restart condition...')
                self.logIt_thread(self.log_path, debug=False, msg=f'Calling self.restart({con}, {ip})...')
                if self.restart(con, ip):
                    break

            # Clear Screen
            elif int(cmd) == 7:
                self.logIt_thread(self.log_path, debug=False, msg=f'Running clear screen condition...')
                self.logIt_thread(self.log_path, debug=False, msg=f'Clearing screen...')
                os.system('cls')
                self.logIt_thread(self.log_path, debug=False, msg=f'Screen cleared.')
                continue

            # Back
            elif int(cmd) == 8:
                self.logIt_thread(self.log_path, debug=False, msg=f'Running back condition...')
                self.logIt_thread(self.log_path, debug=False, msg=f'Breaking shell loop...')
                break

        self.logIt_thread(self.log_path, debug=False, msg=f'=== End of shell() ===')

    def remove_lost_connection(self, con: str, ip: str) -> bool:
        self.logIt_thread(self.log_path, msg=f'Running remove_lost_connection({con}, {ip})...')
        try:
            self.logIt_thread(self.log_path, msg=f'Removing connections...')
            for conKey, ipValue in self.clients.items():
                if conKey == con:
                    for ipKey, identValue in ipValue.items():
                        if ipKey == ip:
                            for identKey, userValue in identValue.items():
                                self.targets.remove(con)
                                self.ips.remove(ip)

                                del self.connections[con]
                                del self.clients[con]
                                print(f"[{colored('*', 'red')}]{colored(f'{ip}', 'yellow')} | "
                                      f"{colored(f'{identKey}', 'yellow')} | "
                                      f"{colored(f'{userValue}', 'yellow')} "
                                      f"Removed from Availables list.\n")

            self.logIt_thread(self.log_path, msg=f'Connections removed.')
            return True

        except RuntimeError as e:
            self.logIt_thread(self.log_path, msg=f'Runtime Error: {e}.')
            return False

    def server_information(self):
        self.logIt_thread(self.log_path, msg=f'Running show server information...')
        last_reboot = psutil.boot_time()
        # print(f"\n[{colored('*', 'cyan')}]Server running on IP: {self.serverIp} | Port: {self.serverPort}")
        # print(f"[{colored('*', 'cyan')}]Server's last restart: "
        #       f"{datetime.fromtimestamp(last_reboot).replace(microsecond=0)}")
        # print(f"[{colored('*', 'cyan')}]Connected Stations: {len(self.targets)}\n")
        data = {
            'Server_IP': self.serverIP,
            'Server_Port': self.port,
            'Last_Boot': datetime.fromtimestamp(last_reboot).replace(microsecond=0),
            'Connected_Stations': len(self.targets)
        }

        label = Label(self.top_bar_label, text=f"\t\t\t\t\tServer IP: {self.serverIP}\t\tServer Port: {self.port}\t\t"
                                               f"Last Boot: {datetime.fromtimestamp(last_reboot).replace(microsecond=0)}\t\t"
                                               f"Connected Stations: {len(self.targets)}", anchor=CENTER)
        label.grid(row=0, sticky='w')

        return data

    def headline(self) -> None:
        print("\n\t\t▄███████▄    ▄████████    ▄████████  ▄████████    ▄█    █▄")
        print("\t\t███    ███   ███    ███   ███    ███ ███    ███   ███    ███")
        print("\t\t███    ███   ███    █▀    ███    ███ ███    █▀    ███    ███")
        print("\t\t███    ███  ▄███▄▄▄       ███    ███ ███         ▄███▄▄▄▄███▄▄")
        print("\t\t▀█████████▀  ▀▀███▀▀▀     ▀███████████ ███        ▀▀███▀▀▀▀███▀")
        print("\t\t███          ███    █▄    ███    ███ ███    █▄    ███    ███")
        print("\t\t███          ███    ███   ███    ███ ███    ███   ███    ███")
        print("\t\t▄████▀        ██████████   ███    █▀  ████████▀    ███    █▀")
        print(f""
              f"\t\t{colored('|| By Gil Shwartz', 'green')} {colored('@2022 ||', 'yellow')}\n")

        print(f"\t\t({colored('1', 'yellow')})Remote Control          ---------------> "
              f"Show Remote Commands")
        print(f"\t\t({colored('2', 'yellow')})Connection History      ---------------> "
              f"Show connection history.")
        print(f"\t\t({colored('3', 'yellow')})Show Connected Stations ---------------> "
              f"Display Current connected stations")
        print(f"\t\t({colored('4', 'yellow')})CLS                     ---------------> "
              f"Clear Local Screen")
        print(f"\t\t({colored('5', 'yellow')})Server Info             ---------------> "
              f"Show Server Information")
        print(f"\t\t({colored('6', 'yellow')})Update clients          ---------------> "
              f"Send an update command to connected clients")
        print(f"\n\t\t({colored('7', 'red')})Exit                     ---------------> "
              f"Close connections and exit program.\n")

        app.logIt_thread(log_path, debug=False, msg=f'=== End of headline() ===')


def get_date() -> str:
    d = datetime.now().replace(microsecond=0)
    dt = str(d.strftime("%b %d %Y | %I-%M-%S"))

    return dt


def main(ip: str, port: int) -> None:
    def headline() -> None:
        app.logIt_thread(log_path, debug=False, msg=f'Running headline()...')
        app.logIt_thread(log_path, debug=False, msg=f'Displaying banner...')
        print("\n\t\t▄███████▄    ▄████████    ▄████████  ▄████████    ▄█    █▄")
        print("\t\t███    ███   ███    ███   ███    ███ ███    ███   ███    ███")
        print("\t\t███    ███   ███    █▀    ███    ███ ███    █▀    ███    ███")
        print("\t\t███    ███  ▄███▄▄▄       ███    ███ ███         ▄███▄▄▄▄███▄▄")
        print("\t\t▀█████████▀  ▀▀███▀▀▀     ▀███████████ ███        ▀▀███▀▀▀▀███▀")
        print("\t\t███          ███    █▄    ███    ███ ███    █▄    ███    ███")
        print("\t\t███          ███    ███   ███    ███ ███    ███   ███    ███")
        print("\t\t▄████▀        ██████████   ███    █▀  ████████▀    ███    █▀")
        print(f""
              f"\t\t{colored('|| By Gil Shwartz', 'green')} {colored('@2022 ||', 'yellow')}\n")

        app.logIt_thread(log_path, debug=False, msg=f'Displaying options...')
        print(f"\t\t({colored('1', 'yellow')})Remote Control          ---------------> "
              f"Show Remote Commands")
        print(f"\t\t({colored('2', 'yellow')})Connection History      ---------------> "
              f"Show connection history.")
        print(f"\t\t({colored('3', 'yellow')})Show Connected Stations ---------------> "
              f"Display Current connected stations")
        print(f"\t\t({colored('4', 'yellow')})CLS                     ---------------> "
              f"Clear Local Screen")
        print(f"\t\t({colored('5', 'yellow')})Server Info             ---------------> "
              f"Show Server Information")
        print(f"\t\t({colored('6', 'yellow')})Update clients          ---------------> "
              f"Send an update command to connected clients")
        print(f"\n\t\t({colored('7', 'red')})Exit                     ---------------> "
              f"Close connections and exit program.\n")

        app.logIt_thread(log_path, debug=False, msg=f'=== End of headline() ===')

    def validate() -> str:
        app.logIt_thread(log_path, msg=f'Waiting for user input...')
        command = input("CONTROL@> ")
        app.logIt_thread(log_path, msg=f'User input: {command}.')

        try:
            app.logIt_thread(log_path, msg=f'Performing input validation on {command}...')
            int(command)

            return command

        except ValueError:
            app.logIt_thread(log_path, msg=f'Wrong input detected.')
            print(
                f"[{colored('*', 'red')}]Numbers only. Choose between "
                f"[{colored('1', 'yellow')} - {colored('7', 'yellow')}].\n")

    def remote_shell() -> bool:
        app.logIt_thread(log_path, msg=f'Running remote shell commands condition...')
        if len(app.clients) != 0:
            print(f"{colored('=', 'blue')}=>{colored('Remote Shell', 'red')}<={colored('=', 'blue')}")

            # Show Available Connections
            app.logIt_thread(log_path, msg=f'Calling server.show_available_connections()...')
            app.show_available_connections()

            # Get Number from User and start Remote Shell
            app.logIt_thread(log_path, msg=f'Calling server.get_station_number()...')
            station = app.get_station_number()
            if station:
                app.logIt_thread(log_path, msg=f'Calling server.shell({station[1]}, {station[2]})...')
                if app.shell(station[1], station[2]):
                    return True

        else:
            app.logIt_thread(log_path, msg=f'No available connections.')
            print(f"[{colored('*', 'cyan')}]No available connections.")
            return False

    def choices() -> None:
        app.logIt_thread(log_path, msg=f'Validating input number is in the menu...')
        if int(command) <= 0 or int(command) > 7:
            print(f"[{colored('*', 'red')}]Wrong Number. [{colored('1', 'yellow')} - {colored('7', 'yellow')}]!")
            return False

        # Remote Shell Commands
        if int(command) == 1:
            app.logIt_thread(log_path, msg=f'Running remote shell condition...')
            if len(app.ips) == 0 and len(app.targets) == 0:
                app.logIt_thread(log_path, msg=f'No available connections.')
                print(f"[{colored('*', 'cyan')}]No connected stations.")
                return False

            remote_shell()

        # Connection History
        elif int(command) == 2:
            app.logIt_thread(log_path, msg=f'Check if connection history list is empty...')
            if len(app.connHistory) == 0:
                app.logIt_thread(log_path, msg=f'List is empty.')
                print(f"[{colored('*', 'cyan')}]List is empty.")
                return False

            app.logIt_thread(log_path, msg=f'Calling server.connection_history()...')
            app.connection_history()
            return

        # Vital Signs - Show Connected Stations
        elif int(command) == 3:
            app.logIt_thread(log_path, msg=f'Running show connected stations condition...')
            if len(app.ips) == 0 and len(app.targets) == 0:
                app.logIt_thread(log_path, msg=f'No available connections.')
                print(f"[{colored('*', 'cyan')}]No connected stations.")
                return False

            print(f"{colored('=', 'blue')}=>{colored('Vital Signs', 'red')}<={colored('=', 'blue')}")
            print(f"[{colored('1', 'green')}]Start | "
                  f"[{colored('2', 'cyan')}]Back\n")

            app.logIt_thread(log_path, msg=f'Calling server.vital_signs()...')
            app.vital_signs()

        # Clear Screen
        elif int(command) == 4:
            app.logIt_thread(log_path, msg=f'Running clear screen...')
            app.logIt_thread(log_path, msg=f'Calling headline()...')
            os.system('cls')

        # Show Server's Information
        elif int(command) == 5:
            app.logIt_thread(log_path, msg=f'Running show server information...')
            last_reboot = psutil.boot_time()
            print(f"\n[{colored('*', 'cyan')}]Server running on IP: {app.serverIp} | Port: {app.serverPort}")
            print(f"[{colored('*', 'cyan')}]Server's last restart: "
                  f"{datetime.fromtimestamp(last_reboot).replace(microsecond=0)}")
            print(f"[{colored('*', 'cyan')}]Connected Stations: {len(app.targets)}\n")
            data = {
                'Server_IP': serverIP,
                'Server_Port': port,
                'Last_Boot': datetime.fromtimestamp(last_reboot).replace(microsecond=0),
                'Connected_Stations': len(app.targets)
            }

            return data

        # Send Update command
        elif int(command) == 6:
            if len(app.ips) == 0 and len(app.targets) == 0:
                app.logIt_thread(log_path, msg=f'No available connections.')
                print(f"[{colored('*', 'cyan')}]No connected stations.")
                return False

            for client, ip in zip(app.targets, app.ips):
                app.logIt_thread(log_path, msg=f'Sending update command to {ip}...')
                client.send('update'.encode())
                app.logIt_thread(log_path, msg=f'Update command sent.')
                app.logIt_thread(log_path, msg=f'Waiting for response from {ip}...')
                msg = client.recv(1024).decode()
                app.logIt_thread(log_path, msg=f'Response from {ip}: {msg}')

        # Exit Program
        elif int(command) == 7:
            app.logIt_thread(log_path, msg=f'User input: 6 | Exiting app...')

            if len(app.targets) > 0:
                try:
                    for t in app.targets:
                        app.logIt_thread(log_path, msg=f'Sending exit command to connected stations...')
                        t.send('exit'.encode())
                        app.logIt_thread(log_path, msg=f'Send completed.')

                        app.logIt_thread(log_path, msg=f'Closing socket connections...')
                        t.close()
                        app.logIt_thread(log_path, msg=f'Socket connections closed.')

                except ConnectionResetError as e:
                    app.logIt_thread(log_path, debug=True, msg=f'Connection Error: {e}.')
                    print(f"[{colored('X', 'red')}]Connection Reset by client.")

                    app.logIt_thread(log_path, debug=True, msg=f'Exiting app with code 1...')
                    sys.exit(1)

            app.logIt_thread(log_path, msg=f'Exiting app with code 0...')
            sys.exit(0)

    while True:
        app.logIt_thread(log_path, msg=f'Running main()...')
        app.logIt_thread(log_path, msg=f'Calling headline()...')
        headline()

        app.logIt_thread(log_path, msg=f'Calling validate()...')
        command = validate()
        app.logIt_thread(log_path, msg=f'Validated command: {command}')

        app.logIt_thread(log_path, msg=f'Calling choices()...')
        choices()


if __name__ == '__main__':
    app = App()
    app.mainloop()

    # COLORS
    # root = tk.Tk()
    # app = ColorChart(root)
    # root.mainloop()

    # mainThread = Thread(target=app.run, name="Server Thread")
    # mainThread.daemon = True
    # mainThread.start()
