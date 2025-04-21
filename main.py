
B = '''[1;30m'''
R = '''[1;31m'''
G = '''[1;32m'''
Y = '''[1;33m'''
Bl = '''[1;34m'''
P = '''[1;35m'''
C = '''[1;36m'''
W = '''[1;37m'''
OB = '''[40m'''
OR = '''[41m'''
OG = '''[42m'''
OY = '''[43m'''
OBl = '''[44m'''
OP = '''[45m'''
OC = '''[46m'''
OW = '''[47m'''
import sys
import os 
import datetime
import codecs
import random
import time
import base64
import socket
import threading
import select
import re
import requests
from datetime import datetime
global roomretst
import random
import requests
import sys






	
	
def generate_random_color():
	color_list = [
    "[00FF00][b][c]",
    "[FFDD00][b][c]",
    "[3813F3][b][c]",
    "[FF0000][b][c]",
    "[0000FF][b][c]",
    "[FFA500][b][c]",
    "[DF07F8][b][c]",
    "[11EAFD][b][c]",
    "[DCE775][b][c]",
    "[A8E6CF][b][c]",
    "[7CB342][b][c]",
    "[FF0000][b][c]",
    "[FFB300][b][c]",
    "[90EE90][b][c]"
]
	random_color = random.choice(color_list)
	return  random_color    
	
	
	
	
def gen_squad(clisocks, packet: str):
        header = packet[0:62]
        lastpacket = packet[64:]
        squadcount = "04"
        NewSquadData = header + squadcount + lastpacket
        clisocks.send(bytes.fromhex(NewSquadData))
def gen_msg4(packet, content):
        content = content.encode("utf-8")
        content = content.hex()
        header = packet[0:8]
        packetLength = packet[8:10]
        packetBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2 = packet[34:62]
        pyloadlength = packet[62:64]
        pyloadtext= re.findall(r"{}(.*?)28".format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+64):]
        NewTextLength = (hex((int(f"0x{pyloadlength}", 16) - int(len(pyloadtext)//2) ) + int(len(content)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f"0x{packetLength}", 16) - int((len(pyloadtext))//2) ) ) + int(len(content)//2) )[2:]
        NewPyloadLength = hex(((int(f"0x{pyloadbodyLength}", 16) - int(len(pyloadtext)//2)))+ int(len(content)//2) )[2:]
        NewMsgPacket = header + NewpaketLength + packetBody + NewPyloadLength + pyloadbody2 + NewTextLength + content + pyloadTile
        return str(NewMsgPacket)
        
        
        
        



                  
import requests
import json
def pc(data):
    url = "http://192.168.1.117:5000/data"  # استبدل <YOUR_COMPUTER_IP> بعنوان IP الخاص بجهاز الكمبيوتر الخاص بك
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, data=json.dumps(data), headers=headers)
    print("Server response:", response.json())
def gen_msgv3(packet , replay):
        replay = replay.encode('utf-8')
        replay = replay.hex()
        hedar = packet[0:8]
        packetLength = packet[8:10] #
        paketBody = packet[10:32]
        pyloadbodyLength = packet[32:34]
        pyloadbody2= packet[34:60]
        pyloadlength = packet[60:62]
        pyloadtext= re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+62):]
        NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
        if len(NewTextLength) == 1:
                NewTextLength = "0"+str(NewTextLength)
        NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
        NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)))+ int(len(replay)//2) )[2:]
        finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
        return str(finallyPacket)
def send_packt(cheack,packet):
    port = 39699
    host = "98.98.162.21"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        message = cheack + packet
        print(R)
        print(message)
        s.sendall(message.encode())
        print(Y)
        print(s.sendall(message.encode()))
        data = s.recv(1024)
        print(C)
        print(data)
        return data
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()
def send_msg(sock, packet, content, delay:int):
        time.sleep(delay)
        try:
                sock.send(bytes.fromhex(gen_msg4(packet, content)))              
                sock.send(bytes.fromhex(gen_msgv3(packet, content)))
        except Exception as e:
                pass
roomretst = False
gameplayed= 0
listt =[]
serversocket =None
remotesockett = None
clienttsocket =None
istarted = False
start =None
stop =b'\x03\x15\x00\x00\x00\x10\t\x1e\xb7N\xef9\xb7WN5\x96\x02\xb0g\x0c\xa8'
increase =False
socktion =None
SOCKS_VERSION = 5
packet =b''
full = False
import requests
def shorten_url(long_url):
    api_url = "https://cleanuri.com/api/v1/shorten"
    data = {"url": long_url}
    response = requests.post(api_url, data=data)
    if response.status_code == 200:
        return response.json()["result_url"]
    else:
        return None
import datetime
import requests
def getdate(playerid):
    global data,dc
    data = requests.get(f"http://88.198.53.59:19350/info/{playerid}").text
    dc = data[9:19]
    try:
        old_date = datetime.strptime(dc, "%d/%m/%Y")
        now = datetime.now()
        delta = now - old_date
        years = delta.days // 365
        months = (delta.days % 365) // 30
        days = (delta.days % 365) % 30
        return f"--> {dc}\n\n{years} سـنـوات \n\n{months} شـهـور \n\n{days} يـوم "
    except:
        return f"??? سـنـوات \n\n??? شـهـور \n\n??? يـوم "
def getreg(Id):         
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://shop2game.com",
        "Referer": "https://shop2game.com/app",
        "sec-ch-ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "x-datadome-clientid": "10BIK2pOeN3Cw42~iX48rEAd2OmRt6MZDJQsEeK5uMirIKyTLO2bV5Ku6~7pJl_3QOmDkJoSzDcAdCAC8J5WRG_fpqrU7crOEq0~_5oqbgJIuVFWkbuUPD~lUpzSweEa",
    }
    payload = {
        "app_id": 100067,
        "login_id": f"{Id}",
        "app_server_id": 0,
    }
    response = requests.post(url, headers=headers, json=payload)
    try:
        if response.status_code == 200:
            return response.json()['region']
        else:
            return(f"ERROR")
    except:
        return("Server unknown ??")
def Encrypt_ID(data):
    return ''.join([hex(ord(c))[2:].zfill(2) for c in data])
def Encrypt(length):
    encrypted_length = hex(length)[2:]
    if len(encrypted_length) % 2 != 0:
        encrypted_length = "0" + encrypted_length
def encrypt_packet(packet):
    return ''.join([hex(ord(c))[2:].zfill(2) for c in packet])
def dec_to_hex(decimal):
    hex_value = hex(decimal)[2:]
    return hex_value.zfill(2 * ((len(hex_value) + 1) // 2))
def GenResponsMsg(Msg, Enc_Id):
    try:
        hexmsg = Msg.encode("UTF-8").hex()
        bunner = "902000" + "306"
        bunner = Encrypt_ID(bunner)
        print(f"Encrypted bunner: {bunner}")       
        msg_lenth = len(Msg.encode("UTF-8").hex()) // 2
        msg_lenth = Encrypt(msg_lenth)
        print(f"Encrypted message length: {msg_lenth}")        
        packet = f"089583bab21f10{Enc_Id}180222{msg_lenth}{hexmsg}28bed88eaa064a180a0b536f756c38473651325f3220c9013802420437d8a3365202656e6a04100118017200"
        payload_lenth = len(packet) // 2
        payload_lenth = Encrypt(payload_lenth)
        print(f"Encrypted payload length: {payload_lenth}")     
        packet = f"080112{payload_lenth}089583bab21f10{Enc_Id}180222{msg_lenth}{hexmsg}28bed88eaa064a180a0b536f756c38473651325f3220c9013802420437d8a3365202656e6a04100118017200"
        encrypted_packet = encrypt_packet(packet)
        header_lenth = len(encrypted_packet) // 2
        header_lenth = dec_to_hex(header_lenth)
        print(f"Header length: {header_lenth}")        
        if len(header_lenth) == 2:
            final_packet = "1215000000" + header_lenth + encrypted_packet
        elif len(header_lenth) == 3:
            final_packet = "121500000" + header_lenth + encrypted_packet
        elif len(header_lenth) == 4:
            final_packet = "12150000" + header_lenth + encrypted_packet
        elif len(header_lenth) == 5:
            final_packet = "1215000" + header_lenth + encrypted_packet
        else:
            raise ValueError("Header length is not within expected range.")        
        return bytes.fromhex(final_packet).hex()    
    except:
        return bytes.fromhex(final_packet).hex()        
def getname(Id):    
    url = "https://shop2game.com/api/auth/player_id_login"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://shop2game.com",
        "Referer": "https://shop2game.com/app",
        "sec-ch-ua": '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "x-datadome-clientid": "10BIK2pOeN3Cw42~iX48rEAd2OmRt6MZDJQsEeK5uMirIKyTLO2bV5Ku6~7pJl_3QOmDkJoSzDcAdCAC8J5WRG_fpqrU7crOEq0~_5oqbgJIuVFWkbuUPD~lUpzSweEa",
    }
    payload = {
        "app_id": 100067,
        "login_id": f"{Id}",
        "app_server_id": 0,
    }
    response = requests.post(url, headers=headers, json=payload)
    try:
        if response.status_code == 200:
            return response.json()['nickname']
        else:
            return("ERROR")
    except:
        return("Name unknown??")
def get_status(Id):
    r= requests.get('https://ff.garena.com/api/antihack/check_banned?lang=en&uid={}'.format(Id)) 
    a = "0"
    try : 
        if  a in r.text :
            return("This account is not banne")
        else: 
            return("This account is banne")
    except:
        return("o !!!!")
def get_inc(id):
    accountid = id
    url = 'https://vrxx1337.pythonanywhere.com/?id={}'.format(accountid)
    response = requests.get(url)
    if response.status_code == 200:
        long_text = response.text
    else:
        return("8c8d99a21b")
    ap = 'idenc":'
    dp = '","'
    start_link2 = long_text.find(ap) + len(ap) + 1
    end_link2 = long_text.find(dp, start_link2)
    iud = long_text[start_link2:end_link2]
    return(iud)
def gen_msgv2_clan(replay  , packet):
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:64]
    if "googleusercontent" in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    elif "https" in str(bytes.fromhex(packet)) and "googleusercontent" not in str(bytes.fromhex(packet)):
        pyloadlength = packet[64:68]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+68):]
    else:
        pyloadlength = packet[64:66]#
        pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
        pyloadTile = packet[int(int(len(pyloadtext))+66):]
    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])    
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int(len(pyloadtext)//2) ) - int(len(pyloadlength))) + int(len(replay)//2) + int(len(NewTextLength)))[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2)) -int(len(pyloadlength)) )+ int(len(replay)//2) + int(len(NewTextLength)))[2:]
    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
    return finallyPacket
import re
def gen_msgv2(replay  , packet):
    replay  = replay.encode('utf-8')
    replay = replay.hex()
    hedar = packet[0:8]
    packetLength = packet[8:10] #
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]#
    pyloadbody2= packet[34:60]
    pyloadlength = packet[60:62]#
    pyloadtext  = re.findall(r'{}(.*?)28'.format(pyloadlength) , packet[50:])[0]
    pyloadTile = packet[int(int(len(pyloadtext))+62):]
    NewTextLength = (hex((int(f'0x{pyloadlength}', 16) - int(len(pyloadtext)//2) ) + int(len(replay)//2))[2:])
    if len(NewTextLength) ==1:
        NewTextLength = "0"+str(NewTextLength)
    NewpaketLength = hex(((int(f'0x{packetLength}', 16) - int((len(pyloadtext))//2) ) ) + int(len(replay)//2) )[2:]
    NewPyloadLength = hex(((int(f'0x{pyloadbodyLength}', 16) - int(len(pyloadtext)//2))  )+ int(len(replay)//2) )[2:]
    finallyPacket = hedar + NewpaketLength +paketBody + NewPyloadLength +pyloadbody2+NewTextLength+ replay + pyloadTile
    return finallyPacket
def inret():
    global hidd,packet1
    try:
        hidd.send(packet1)
    except:
        pass
def nret():
    global vispacket,visback
    try:
        visback.send(vispacket)
    except:
        pass
def sendi():
    global snv,dataC
    while True:
        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 900:
            for i in range(400):
                snv.send(dataC)
                for k in range(1):
                    time.sleep(0.001)
            break
error = None
preventlag = False
sqlag = False
st = False
serversocket = None
clientsocket =None
op = None
pekto =None
inviteD=False
spampacket= b''
recordmode= False
sendpackt=False
back = False
spy = False
resasa =False
id_view = None
rolp = False
comand =True
cheak = False
mess = False
msgs =False
SOCKS_VERSION = 5
packet = b''
packet1 = b''
invite = None
invite = None
returntoroom = False
roomp = False
number = 0
def roompass():
    global roomp
    if roomp == True:
        return True
    else:
        return False
def roomst():
    if roompass() == True:
        try:
            return str(number)
        except:
            return "BYTE BOT"
def xmodz(xmod):
      for k in range(90000):
          xmod.send(b'\x0e\x15\x00\x00\x00P\xd6\xd5\x19\x00+\xdc\xc6M\xe8\xa4,\x1a\xae\xdf\\:\xaa\xcf|\xe6\x94\xef\xbf\xc1\xf1\x1f\x02h\t\xb6%\xe7\x93aM\xd1?\xfa8\xee\xccUO\xf3 \xa6\x1b\x8a\xc6\x96\x99\xa8\xeb^\xda\xb7;9\xe9\xd9\x10zP\xd5\xe0\x83\xa2\xbc\x8c\x01\xfb\xadd\xdb\xcek\x85\x81\xcdP')
          for l in range(1):
              time.sleep(0.05)
def lagroom(cli,lg):
            for I in range(10):               
                time.sleep(1)
                cli.send(b'\x0e\x15\x00\x00\x00\x10\x02\x92L\xf4)[\xa9xk^\xca\xf6\x8a\x80~w')
                time.sleep(1)
                cli.send(lg)
from time import sleep
global cmode
cmode = False
def crmode(value7):
    global cmode
    cmode = value7
    return cmode

def crazymode(teams,solo,packett):
        for i in range(20):
        	time.sleep(0.8)
        	keam.send(printkt)
        	time.sleep(0.8)
        	keam.send(printkt1)
def randm(keam,printkt1,printkt):
        for i in range(3):
        	time.sleep(1)
        	keam.send(printkt)
        	time.sleep(1)
        	keam.send(printkt1)
def BesTo_msg(mess, data, clin):
    data = data[12:22]
    api_url = f"https://c4-team-generate-bb-99uyq.vercel.app/GeneRate-PaCKet-Msg?Id={data}&Msg={mess}&Key=plya-ii9ip"
    try:
        response = requests.get(api_url)
        response.raise_for_status() 
        packet = response.text
        clin.send(bytes.fromhex(packet.strip('"')))
    except requests.exceptions.RequestException as e:
        return f"An error occurred: {e}"
    except requests.exceptions.RequestException as e:
        return f"An error occurred: {e}"    



################################ 



import requests

def likes_plus(uid, region="ME"):
    url = f"https://ff-likes-rbgx.vercel.app/like?key=rbgxKs&uid={uid}&region={region}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return f"""- PlaYer > {data.get('player', 'ErRor')}
- LeVeL > {data.get('level', 'ErRor')}
- LikEs BeFOrE > {data.get('likes_before', 0)}
- LikEs AFTeR > {data.get('likes_after', 0)}
- LikEs AddeD > {data.get('likes_added', 0)}"""
        else:
            return f"حدث خطأ، كود الحالة : {response.status_code}"
    except Exception as e:
        return f"حدث خطأ: {e}"
 



      
 
################################                                            


def send_spam(uid):
    url = f"https://ff-spam-rbgx.vercel.app/spam?key=rbgxPo&uid={uid}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if "message" in data:  # تحقق من وجود الرسالة في الاستجابة
                return f" {data['message']}"
            else:
                return f"تم إرسال السبام إلى {uid} بنجاح !"
        else:
            return f" حدث خطأ، كود الحالة : {response.status_code}"
    except Exception as e:
        return f" حدث خطأ: {e}"
        

                
                        
################################                                 
                                                
def info(go):
    pack = "في فريق"
    api_url = f"https://send-info-fadai.vercel.app/api?id={pack}&lop={go}"
    try:
        response = requests.get(api_url)
        response.raise_for_status() 
        final = response.text
        return final
    except:
        pass       	
def find_name_and_value(value):
    if value == 1000 or (value < 1050 and value > 1000):
        return "Brounze1", 1000
    elif value == 1050 or (value < 1150 and value > 1050):
        return "Brounze2", 1050
    elif value == 1150 or (value < 1250 and value > 1150):
        return "Brounze3", 1150
    elif value == 1250 or (value < 1350 and value > 1250):
        return "Silver1", 1250
    elif value == 1350 or (value < 1450 and value > 1350):
        return "Silver2", 1350
    elif value == 1450 or (value < 1550 and value > 1450):
        return "Silver3", 1450
    elif value == 1550 or (value < 1663 and value > 1550):
        return "Gold1", 1550
    elif value == 1663 or (value < 1788 and value > 1663):
        return "Gold2", 1663
    elif value == 1788 or (value < 1913 and value > 1788):
        return "Gold3", 1788
    elif value == 1913 or (value < 2038 and value > 1913):
        return "Gold4", 1913
    elif value == 2038 or (value < 2163 and value > 2038):
        return "Platinum1", 2038
    elif value == 2163 or (value < 2288 and value > 2163):
        return "Platinum2", 2163
    elif value == 2288 or (value < 2413 and value > 2288):
        return "Platinum3", 2288
    elif value == 2413 or (value < 2538 and value > 2413):
        return "Platinum4", 2413
    elif value == 2538 or (value < 2675 and value > 2538):
        return "Diamond1", 2538
    elif value == 2675 or (value < 2825 and value > 2675):
        return "Diamond2", 2675
    elif value == 2825 or (value < 2975 and value > 2825):
        return "Diamond3", 2825
    elif value == 2975 or (value < 3125 and value > 2975):
        return "Diamond4", 2975
    elif value == 3125 or value > 3125:
        return "Heroic", 3125
    else:
        return "Value not found", None
def timr_sleep():
     global cheak
     cheak = False
     time.sleep(2)
     cheak = True
def stoplg(rsend,leg,resocket,clsocket):
   preventlag = False
   for i in range(1):
      time.sleep(2)
      for h in range(1):
         rsend.send(b'\x0e\x15\x00\x00\x00\x10\x02\x92L\xf4)[\xa9xk^\xca\xf6\x8a\x80~w')
         for t in range(1):
            time.sleep(2)
            for k in range(1):
               rsend.send(leg)
import requests
def adjust_text_length(text, target_length=22, fill_char="20"):
    if len(text) > target_length:
        return text[:target_length]
    elif len(text) < target_length:
        fill_length = target_length - len(text)
        return text + (fill_char * (fill_length // len(fill_char)))[:fill_length]
    else:
        return text
def enc(data):
    api_url = "https://beryl-bubbly-nemophila.glitch.me/api/ffenc"
    id = data
    url = f"{api_url}?q={id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return f"Error: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
global spprspm
def spprspm(server,packet):
        while True:
            time.sleep(0.014)
            server.send(packet)
            if msgs == False:
                break
fivesq = False
def fivepe(value23):
    global fivesq
    fivesq = value23
    return fivesq
def runsnv():
    threading.Thread(target=sendi).start()
SOCKS_VERSION = 5
class Proxy:
    def __init__(self):
        self.username = "1"
        self.password = "1"
        self.website = "https://api-ghost.vercel.app/FFcrypto/{id}"
        self.packet = b''
        self.sendmode = 'client-0-'
        global connection
        
    def fake_friend(client, id: str):
        if len(id) == 8:
            packet = "060000007708d4d7faba1d100620022a6b08cec2f1051a1b5b3030464630305d2b2b20202020524247585b3030464630305d32024d454049b00101b801e807d801d4d8d0ad03e001b2dd8dae03ea011eefbca8efbca5efbcb2efbcafefbcb3efbca8efbca9efbcadefbca1efa3bf8002fd98a8dd03900201d00201"
            packet = re.sub(r'cec2f105', id, packet)
            client.send(bytes.fromhex(packet))
        elif len(id) == 10:
            packet = "060000006f08d4d7faba1d100620022a6308fb9db9ae061a1c5b3030464630305d2b2be385a45242475820205b3030464630305d32024d454040b00113b801e71cd801d4d8d0ad03e00191db8dae03ea010a5a45522d49534b494e47f00101f801911a8002fd98a8dd03900201d0020ad80221"
            packet = re.sub(r'fb9db9ae06', id, packet)
            client.send(bytes.fromhex(packet))
        else:
            print(id)
    def Encrypt_ID(id):
        api_url = website.format(id=id)
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                return response.text
            else:
                pass
                return None
        except requests.RequestException as e:
            pass
            return None
            
    def handle_client(self, connection):
        version, nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection)
        if 2   in set(methods):
            if 2 in set(methods):
                connection.sendall(bytes([SOCKS_VERSION, 2]))
            else:
                connection.sendall(bytes([SOCKS_VERSION, 0]))
        if not self.verify_credentials(connection,methods):
            return
        version, cmd, _, address_type = connection.recv(4)
        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)
            name= socket.gethostname()
        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        port2 = port
        try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                addr = int.from_bytes(socket.inet_aton(
                    bind_address[0]), 'big', signed=False)
                port = bind_address[1]
                reply = b''.join([
                    SOCKS_VERSION.to_bytes(1, 'big'),
                    int(0).to_bytes(1, 'big'),
                    int(0).to_bytes(1, 'big'),
                    int(1).to_bytes(1, 'big'),
                    addr.to_bytes(4, 'big'),
                    port.to_bytes(2, 'big')
            ])
        except Exception as e:
            reply = self.generate_failed_reply(address_type, 5)
        connection.sendall(reply)
        self.botdev(connection, remote,port2)
    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])
    def verify_credentials(self, connection,methods):
        if 2 in methods:
            version = ord(connection.recv(1))
            username_len = ord(connection.recv(1))
            username = connection.recv(username_len).decode('utf-8')
            password_len = ord(connection.recv(1))
            password = connection.recv(password_len).decode('utf-8')
            if username == self.username and password == self.password:
                response = bytes([version, 0])
                connection.sendall(response)
                return True
            response = bytes([version, 0])
            connection.sendall(response)
            return True
        else:
            version =1
            response = bytes([version, 0])
            connection.sendall(response)
            return True
    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods
    def runs(self, host, port):
        var =  0
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        while True:
            var =var+1
            conn, addr = s.accept()
            running = False
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start() 
    def botdev(self, client, remote, port):
        global clientC
        global remoteC
        global clientM
        global op
        global back
        global pekto
        global x
        global o
        global k
        o = True
        k = False
        x = False
        global b
        b = False
        global c
        c = False
        idinfo = True
        yout1 = b"\x06\x00\x00\x00{\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*o\x08\x81\x80\x83\xb6\x01\x1a)[18ffff]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf\xe3\x85\xa4\xd8\xa7\xd9\x84\xd8\xa8\xd9\x87\xd8\xa7\xd8\xa6\xd9\x85[18ffff]2\x02ME@N\xb0\x01\x13\xb8\x01\xdc)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\tAO'-'TEAM\xf0\x01\x01\xf8\x01\xdc\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02F"
        yout2 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xd6\xd1\xb9(\x1a![18ffff]\xef\xbc\xa8\xef\xbc\xac\xe3\x85\xa4Hassone.[18ffff]2\x02ME@G\xb0\x01\x13\xb8\x01\xcf\x1e\xd8\x01\xcc\xd6\xd0\xad\x03\xe0\x01\xed\xdc\x8d\xae\x03\xea\x01\x1d\xef\xbc\xb4\xef\xbc\xa8\xef\xbc\xa5\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xac\xef\xbc\xac\xe0\xbf\x90\xc2\xb9\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout3 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xe9\xa7\xe9\x1b\x1a [18ffff]DS\xe3\x85\xa4WAJIHANO\xe3\x85\xa4[18ffff]2\x02ME@Q\xb0\x01\x14\xb8\x01\xca2\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x10.DICTATORS\xe3\x85\xa4\xe2\x88\x9a\xf0\x01\x01\xf8\x01\xc4\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+'
        yout4 = b'\x06\x00\x00\x00z\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*n\x08\xed\xd4\xa7\xa2\x02\x1a\x1f[18ffff]M8N\xe3\x85\xa4y\xe3\x85\xa4Fouad[18ffff]2\x02ME@O\xb0\x01\x13\xb8\x01\xa9#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xdb\xdb\x8d\xae\x03\xea\x01\x0cGREAT\xe2\x80\xbfWALL\xf0\x01\x01\xf8\x01b\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\r\xd8\x023\xe0\x02\xc1\xb7\xf8\xb1\x03'
        yout5 = b"\x06\x00\x00\x00\x84\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*x\x08\xb6\xc0\xf1\xcc\x01\x1a'[18ffff]\xd9\x85\xd9\x84\xd9\x83\xd8\xa9*\xd9\x84\xd9\x85\xd8\xb9\xd9\x88\xd9\x82\xd9\x8a\xd9\x86[18ffff]2\x02ME@G\xb0\x01\x05\xb8\x01\x82\x0b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x15\xe9\xbf\x84\xef\xbc\xac\xef\xbc\xaf\xef\xbc\xb2\xef\xbc\xa4\xef\xbc\xb3\xe9\xbf\x84\xf0\x01\x01\xf8\x01>\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x05\xd8\x02\x0e"
        yout6 = b'\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xeb\x98\x88\x8e\x01\x1a"[18ffff]OP\xe3\x85\xa4BNL\xe3\x85\xa4\xe2\x9a\xa1\xe3\x85\xa4*[18ffff]2\x02ME@R\xb0\x01\x10\xb8\x01\xce\x16\xd8\x01\x84\xf0\xd2\xad\x03\xe0\x01\xa8\xdb\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x8f\xe1\xb4\xa0\xe1\xb4\x87\xca\x80\xe3\x85\xa4\xe1\xb4\x98\xe1\xb4\x8f\xe1\xb4\xa1\xe1\xb4\x87\xca\x80\xe2\x9a\xa1\xf0\x01\x01\xf8\x01A\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01\xe0\x02\xf3\x94\xf6\xb1\x03'
        yout7 = b"\x06\x00\x00\x00\x8e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x81\x01\x08\xb0\xa4\xdb\x80\x01\x1a'[18ffff]\xd9\x85\xd9\x83\xd8\xa7\xd9\x81\xd8\xad\xd8\xa9.\xe2\x84\x93\xca\x99\xe3\x80\xb5..[18ffff]2\x02ME@T\xb0\x01\x13\xb8\x01\xfc$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x1d\xef\xbc\xad\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa1\xe3\x85\xa4\xe2\x8e\xb0\xe2\x84\x93\xca\x99\xe2\x8e\xb1\xf0\x01\x01\xf8\x01\xdb\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0f\xd8\x02>"
        yout8 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xfd\x8a\xde\xb4\x02\x1a\x1f[18ffff]ITZ\xe4\xb8\xb6MOHA\xe3\x85\xa42M[18ffff]2\x02ME@C\xb0\x01\n\xb8\x01\xdf\x0f\xd8\x01\xac\xd8\xd0\xad\x03\xe0\x01\xf2\xdc\x8d\xae\x03\xea\x01\x15\xe3\x80\x9dITZ\xe3\x80\x9e\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf8\x01\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x026'
        yout9 = b'\x06\x00\x00\x00w\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*k\x08\xc6\x99\xddp\x1a\x1b[18ffff]HEROSHIIMA1[18ffff]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa8\xef\xbc\xa5\xef\xbc\xb2\xef\xbc\xaf\xef\xbc\xb3\xef\xbc\xa8\xef\xbc\xa9\xef\xbc\xad\xef\xbc\xa1\xef\xa3\xbf\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout10 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[18ffff]SH\xe3\x85\xa4SHIMA|M[18ffff]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03'
        yout11 = b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[18ffff]2JZ\xe3\x85\xa4POWER[18ffff]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03'
        yout12 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[18ffff]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[18ffff]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03'
        yout14 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[18ffff]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[18ffff]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03'
        yout15 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\x90\xf6\x87\x15\x1a"[18ffff]V4\xe3\x85\xa4RIO\xe3\x85\xa46%\xe3\x85\xa4zt[18ffff]2\x02ME@M\xb0\x01\x13\xb8\x01\x95&\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x0e\xe1\xb4\xa0\xe1\xb4\x80\xe1\xb4\x8d\xe1\xb4\x8f\xd1\x95\xf0\x01\x01\xf8\x01\xe2\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02^\xe0\x02\x85\xff\xf5\xb1\x03'
        yout16 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[18ffff]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[18ffff]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 '
        yout17 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[18ffff]SVG.NINJA\xe2\xbc\xbd[18ffff]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?'
        yout18 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[18ffff]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[18ffff]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03"
        yout19 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[18ffff]FARAMAWY_1M.[18ffff]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout20 = b'\x06\x00\x00\x00p\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*d\x08\xde\x91\xb7Q\x1a\x1c[18ffff]SH\xe3\x85\xa4SHIMA|M[18ffff]2\x02ME@R\xb0\x01\x14\xb8\x01\xe7C\xd8\x01\xdd\xd6\xd0\xad\x03\xe0\x01\xca\xdb\x8d\xae\x03\xea\x01\tSH\xe3\x85\xa4Team\xf8\x014\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x11\xd8\x02G\xe0\x02\x89\xa0\xf8\xb1\x03'
        yout21= b'\x06\x00\x00\x00h\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\\\x08\xa1\x9f\xb3\xf4\x01\x1a\x1b[18ffff]2JZ\xe3\x85\xa4POWER[18ffff]2\x02ME@M\xb0\x01\x13\xb8\x01\xa5(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xec\xdb\x8d\xae\x03\xf0\x01\x01\xf8\x01\x9a\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02.\xe0\x02\xb2\xe9\xf7\xb1\x03'
        yout22 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\xaa\xe5\xa4\xe3\x01\x1a-[18ffff]\xe3\x85\xa4\xd8\xb4\xd9\x83\xd8\xa7\xd9\x8e\xd9\x83\xd9\x80\xd9\x8a\xe3\x80\x8e\xe2\x85\xb5\xe1\xb4\x98\xe3\x80\x8f[18ffff]2\x02ME@Q\xb0\x01\x13\xb8\x01\xf2*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xaf\xdb\x8d\xae\x03\xea\x01\x15\xe2\x80\xa2\xe3\x85\xa4\xe2\x93\x8b\xe2\x92\xbe\xe2\x93\x85\xe3\x85\xa4\xe2\x80\xa2\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02e\xe0\x02\xa0\xf1\xf7\xb1\x03'
        yout23 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xfd\x8b\xf4\xfa\x01\x1a$[18ffff]"\xd8\xaf\xd8\xb1\xd8\xa7\xd8\xba\xd9\x88\xd9\x86\xd9\x80\xd9\x88\xd9\x81"[18ffff]2\x02ME@F\xb0\x01\x13\xb8\x01\xec \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe1\xb4\x98\xe1\xb4\x84\xe1\xb5\x80\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\xb0\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x04\xd8\x02\t\xe0\x02\xf2\x94\xf6\xb1\x03'
        yout24 = b'\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xaa\x84\xc1r\x1a\x1f[18ffff]SA777RAWI\xe3\x85\xa4\xe3\x85\xa4[18ffff]2\x02ME@N\xb0\x01\x13\xb8\x01\xc8\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x0cSA7RAWI\xe3\x85\xa4TM\xf0\x01\x01\xf8\x01\xfe\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\t\xd8\x02 '
        yout25 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xe7\xbf\xb6\x8f\x01\x1a\x1c[18ffff]SVG.NINJA\xe2\xbc\xbd[18ffff]2\x02ME@I\xb0\x01\x13\xb8\x01\x94\x1b\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x85\xdb\x8d\xae\x03\xea\x01\x15\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4\xe3\x85\xa4???\xe3\x85\xa4\xe3\x85\xa4\xf0\x01\x01\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02?'
        yout26 = b"\x06\x00\x00\x00\x9d\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x90\x01\x08\xa8\xe8\x91\xd7\x01\x1a.[18ffff]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe4\xba\x97\xef\xbc\xb9\xef\xbc\xb4\xe3\x85\xa4[18ffff]2\x02ME@N\xb0\x01\x13\xb8\x01\x97'\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1e\xef\xbc\xa1\xef\xbc\xac\xef\xbc\x93\xef\xbc\xab\xef\xbc\xa5\xef\xbc\xa4\xe2\x80\xa2\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93\xf0\x01\x01\xf8\x01\xab\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x10\xd8\x02@\xe0\x02\xe9\x80\xf8\xb1\x03"
        yout27 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9b\x94\xaa\r\x1a\x1c[18ffff]FARAMAWY_1M.[18ffff]2\x02ME@I\xb0\x01\x01\xb8\x01\xe8\x07\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01X\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout28 = b"\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xaa\xdd\xf1'\x1a\x1d[18ffff]BM\xe3\x85\xa4ABDOU_YT[18ffff]2\x02ME@G\xb0\x01\x13\xb8\x01\xd4$\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1d\xe2\x80\xa2\xc9\xae\xe1\xb4\x87\xca\x9f\xca\x9f\xe1\xb4\x80\xca\x8d\xe1\xb4\x80\xd2\x93\xc9\xaa\xe1\xb4\x80\xc2\xb0\xf0\x01\x01\xf8\x01\x8e\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x07\xd8\x02\x16"
        yout29 = b'\x06\x00\x00\x00r\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*f\x08\x9a\xd6\xdcL\x1a-[18ffff]\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xe3\x85\xa4\xef\xbc\xa8\xef\xbc\xa1\xef\xbc\xa6\xef\xbc\xa9\xef\xbc\xa4\xef\xbc\xa9[18ffff]2\x02ME@H\xb0\x01\x01\xb8\x01\xe8\x07\xea\x01\x15\xe1\xb4\x8d\xcd\xa1\xcd\x9co\xc9\xb4\xef\xbd\x93\xe1\xb4\x9b\xe1\xb4\x87\xca\x80\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout30 = b'\x06\x00\x00\x00v\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*j\x08\xb6\x92\xa9\xc8\x01\x1a [18ffff]\xef\xbc\xaa\xef\xbc\xad\xef\xbc\xb2\xe3\x85\xa4200K[18ffff]2\x02ME@R\xb0\x01\x13\xb8\x01\xc3(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\n3KASH-TEAM\xf8\x012\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x06\xd8\x02\x13\xe0\x02\x89\xa0\xf8\xb1\x03'
        yout31 = b"\x06\x00\x00\x00\x92\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x85\x01\x08\xa2\xd3\xf4\x81\x07\x1a'[18ffff]\xd8\xb3\xd9\x80\xd9\x86\xd9\x80\xd8\xaf\xd8\xb1\xd9\x8a\xd9\x84\xd8\xa71M\xe3\x85\xa4[18ffff]2\x02ME@K\xb0\x01\x13\xb8\x01\xc1 \xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xad\xef\xbc\xa6\xef\xbc\x95\xef\xbc\xb2\xef\xbc\xa8\xe3\x85\xa4\xe1\xb4\xa0\xc9\xaa\xe1\xb4\x98\xf0\x01\x01\xf8\x01\x8c\x01\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0e\xd8\x024\xe0\x02\x87\xff\xf5\xb1\x03"
        yout32 = b'\x06\x00\x00\x00|\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*p\x08\xe0\xe1\xdeu\x1a\x1a[18ffff]P1\xe3\x85\xa4Fahad[18ffff]2\x02ME@N\xb0\x01\x13\xb8\x01\xd0&\xd8\x01\xea\xd6\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1a\xe3\x85\xa4\xef\xbc\xb0\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xa5\xef\xbc\xae\xef\xbc\xa9\xef\xbc\xb8\xc2\xb9\xf0\x01\x01\xf8\x01\x9e\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02*'
        yout33 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\xc5\xcf\x94\x8b\x02\x1a\x18[18ffff]@EL9YSAR[18ffff]2\x02ME@P\xb0\x01\x13\xb8\x01\x86+\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\x89\xae\x8f\xae\x03\xea\x01\x1d-\xc9\xaa\xe1\xb4\x8d\xe1\xb4\x8d\xe1\xb4\x8f\xca\x80\xe1\xb4\x9b\xe1\xb4\x80\xca\x9fs\xe2\xac\x86\xef\xb8\x8f\xf8\x01j\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xe2\x02\xe0\x02\x9f\xf1\xf7\xb1\x03'
        yout34 = b'\x06\x00\x00\x00x\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*l\x08\xa9\x81\xe6^\x1a\x1e[18ffff]STRONG\xe3\x85\xa4CRONA[18ffff]2\x02ME@J\xb0\x01\x13\xb8\x01\xd8$\xd8\x01\xd8\xd6\xd0\xad\x03\xe0\x01\x92\xdb\x8d\xae\x03\xea\x01\x12\xe2\x80\xa2\xe3\x85\xa4STRONG\xe3\x85\xa4\xe2\x80\xa2\xf0\x01\x01\xf8\x01q\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\xbc\x01'
        yout35 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xeb\x8d\x97\xec\x01\x1a&[18ffff]\xd8\xb9\xd9\x80\xd9\x85\xd9\x80\xd8\xaf\xd9\x86\xd9\x8a\xd9\x80\xd8\xaa\xd9\x80\xd9\x88[18ffff]2\x02ME@F\xb0\x01\x13\xb8\x01\xd3\x1a\xd8\x01\xaf\xd7\xd0\xad\x03\xe0\x01\xf4\xdc\x8d\xae\x03\xea\x01\rOSIRIS\xe3\x85\xa4MASR\xf8\x01o\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02\\\xe0\x02\xf4\x94\xf6\xb1\x03'
        yout36 = b'\x06\x00\x00\x00\x7f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*s\x08\xb4\xff\xa3\xef\x01\x1a\x1c[18ffff]ZAIN_YT_500K[18ffff]2\x02ME@K\xb0\x01\x13\xb8\x01\xa3#\xd8\x01\xa2\xd7\xd0\xad\x03\xe0\x01\xbb\xdb\x8d\xae\x03\xea\x01\x1b\xe1\xb6\xbb\xe1\xb5\x83\xe1\xb6\xa4\xe1\xb6\xb0\xe3\x85\xa4\xe1\xb5\x97\xe1\xb5\x89\xe1\xb5\x83\xe1\xb5\x90\xf0\x01\x01\xf8\x01\\\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0b\xd8\x02('
        yout37 = b'\x06\x00\x00\x00\x8f\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x82\x01\x08\x86\xa7\x9e\xa7\x0b\x1a([18ffff]\xe2\x80\x94\xcd\x9e\xcd\x9f\xcd\x9e\xe2\x98\x85\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8[18ffff]2\x02ME@d\xb0\x01\x13\xb8\x01\xe3\x1c\xe0\x01\xf2\x83\x90\xae\x03\xea\x01!\xe3\x85\xa4\xef\xbc\xa2\xef\xbc\xac\xef\xbc\xb2\xef\xbc\xb8\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf8\x01u\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Y\xe0\x02\xc1\xb7\xf8\xb1\x03'
        yout38 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xc3\xcf\xe5H\x1a([18ffff]\xe3\x85\xa4BEE\xe2\x9c\xbfSTO\xe3\x85\xa4\xe1\xb5\x80\xe1\xb4\xb5\xe1\xb4\xb7[18ffff]2\x02ME@Q\xb0\x01\x14\xb8\x01\xffP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x15TIK\xe2\x9c\xbfTOK\xe1\xb5\x80\xe1\xb4\xb1\xe1\xb4\xac\xe1\xb4\xb9\xf0\x01\x01\xf8\x01\xc8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02q'
        yout39 = b'\x06\x00\x00\x00\x94\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x87\x01\x08\x97\xd5\x9a.\x1a%[18ffff]\xd8\xb9\xd9\x86\xd9\x83\xd9\x88\xd8\xb4\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe3\x85\xa4[18ffff]2\x02ME@P\xb0\x01\x13\xb8\x01\xe8(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x1f\xe1\xb4\x80\xc9\xb4\xe1\xb4\x8b\xe1\xb4\x9c\xea\x9c\xb1\xca\x9c\xe3\x85\xa4\xe1\xb4\x9b\xe1\xb4\x87\xe1\xb4\x80\xe1\xb4\x8d\xf0\x01\x01\xf8\x01\xb6\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02"\xe0\x02\xf2\x94\xf6\xb1\x03'
        yout40 = b'\x06\x00\x00\x00\x8a\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*~\x08\xf7\xdf\xda\\\x1a/[18ffff]\xef\xbc\xa1\xef\xbc\xac\xef\xbc\xa8\xef\xbc\xaf\xef\xbc\xad\xef\xbc\xb3\xef\xbc\xa9_\xef\xbc\xb9\xef\xbc\xb4\xe2\x9c\x93[18ffff]2\x02ME@P\xb0\x01\x13\xb8\x01\xb9*\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xc1\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\x8e\x0e\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02S\xe0\x02\xc3\xb7\xf8\xb1\x03'
        yout41 = b'\x06\x00\x00\x00\x86\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*z\x08\xb5\xdd\xec\x8e\x01\x1a%[18ffff]\xd8\xa7\xd9\x88\xd9\x81\xe3\x80\x80\xd9\x85\xd9\x86\xd9\x83\xe3\x85\xa4\xe2\x9c\x93[18ffff]2\x02ME@K\xb0\x01\x13\xb8\x01\xdd#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x18\xef\xbc\xaf\xef\xbc\xa6\xe3\x85\xa4\xef\xbc\xb4\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xad\xe3\x85\xa4\xf0\x01\x01\xf8\x01\xe8\x02\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02Q'
        yout42 = b'\x06\x00\x00\x00\x8b\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*\x7f\x08\x81\xf4\xba\xf8\x01\x1a%[18ffff]\xef\xbc\xa7\xef\xbc\xa2\xe3\x85\xa4\xef\xbc\xae\xef\xbc\xaf\xef\xbc\x91\xe3\x81\x95[18ffff]2\x02ME@N\xb0\x01\x0c\xb8\x01\xbd\x11\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb1\xdd\x8d\xae\x03\xea\x01\x1a\xef\xbc\xa7\xef\xbc\xb2\xef\xbc\xa5\xef\xbc\xa1\xef\xbc\xb4__\xef\xbc\xa2\xef\xbc\xaf\xef\xbc\xb9\xf8\x018\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02-\xe0\x02\x85\xff\xf5\xb1\x03'
        yout43 = b'\x06\x00\x00\x00o\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*c\x08\xfb\x9d\xb9\xae\x06\x1a\x1c[18ffff]BT\xe3\x85\xa4BadroTV[18ffff]2\x02ME@@\xb0\x01\x13\xb8\x01\xe7\x1c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x91\xdb\x8d\xae\x03\xea\x01\nBadro_TV_F\xf0\x01\x01\xf8\x01\x91\x1a\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\n\xd8\x02!'
        yout44 = b"\x06\x00\x00\x00s\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*g\x08\xc4\xe5\xe1>\x1a'[18ffff]\xd8\xb5\xd8\xa7\xd8\xa6\xd8\xaf~\xd8\xa7\xd9\x84\xd8\xba\xd9\x86\xd8\xa7\xd8\xa6\xd9\x85[18ffff]2\x02ME@J\xb0\x01\x14\xb8\x01\xceP\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x03Z7F\xf0\x01\x01\xf8\x01\xd0\x19\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x14\xd8\x02\x9c\x01"
        yout45 = b'\x06\x00\x00\x00\x85\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*y\x08\xfd\xa4\xa6i\x1a$[18ffff]\xd8\xb2\xd9\x8a\xd9\x80\xd8\xb1\xc9\xb4\xcc\xb67\xcc\xb6\xca\x80\xe3\x85\xa4[18ffff]2\x02ME@M\xb0\x01\x13\xb8\x01\xe1(\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x19\xc2\xb7\xe3\x85\xa4\xe3\x85\xa4N\xe3\x85\xa47\xe3\x85\xa4R\xe3\x85\xa4\xe3\x85\xa4\xc2\xb7\xf0\x01\x01\xf8\x01\x8f\t\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02k'
        yout46 = b'\x06\x00\x00\x00y\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*m\x08\xcc\xb9\xcc\xd4\x06\x1a"[18ffff]\xd8\xa8\xd9\x88\xd8\xad\xd8\xa7\xd9\x83\xd9\x80\xd9\x80\xd9\x80\xd9\x85[18ffff]2\x02ME@9\xb0\x01\x07\xb8\x01\xca\x0c\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x11*\xef\xbc\x97\xef\xbc\xaf\xef\xbc\xab\xef\xbc\xa1\xef\xbc\xad*\xf0\x01\x01\xf8\x01\xad\x05\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x01'
        yout47 = b'\x06\x00\x00\x00e\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*Y\x08\xe8\xbd\xc9b\x1a [18ffff]\xe3\x80\x8cvip\xe3\x80\x8dDR999FF[18ffff]2\x02ME@Q\xb0\x01\x10\xb8\x01\x94\x16\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xf0\x01\x01\xf8\x01\xa0\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x0c\xd8\x02+'
        yout48 = b'\x06\x00\x00\x00\x82\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*v\x08\x86\xb7\x84\xf1\x01\x1a&[18ffff]\xd8\xa2\xd9\x86\xd9\x8a\xd9\x80\xd9\x80\xd9\x84\xd8\xa7\xce\x92\xe2\x92\x91\xe3\x85\xa4[18ffff]2\x02ME@Q\xb0\x01\x13\xb8\x01\x82)\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xb2\xdd\x8d\xae\x03\xea\x01\x13\xce\x92\xe2\x92\x91\xe3\x85\xa4MAFIA\xe3\x85\xa4\xef\xa3\xbf\xf0\x01\x01\xf8\x01\x95\x04\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02W'
        yout49 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [18ffff]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[18ffff]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
        yout50 = b'\x06\x00\x00\x00u\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x02*i\x08\xb4\xbe\xde\x83\x02\x1a [18ffff]SPONGEBOB!\xe3\x85\xa4\xe4\xba\x97[18ffff]2\x02ME@N\xb0\x01\x14\xb8\x01\x842\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\x96\xdb\x8d\xae\x03\xea\x01\x0cALHOMSI~TEAM\xf0\x01\x01\xf8\x01\xbd\x03\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\x13\xd8\x02{'
        yout51 = b'\x06\x00\x00\x00z\x08\xd4\xd7\xfa\xba\x1d\x10\x06 \x028c8d99a21bn\x08\xed\xd4\xa7\xa2\x02\x1a\x1f[18ffff]M8N\xe3\x85\xa4y\xe3\x85\xa4Fouad[18ffff]2\x02ME@O\xb0\x01\x13\xb8\x01\xa9#\xd8\x01\xd4\xd8\xd0\xad\x03\xe0\x01\xdb\xdb\x8d\xae\x03\xea\x01\x0cGREAT\xe2\x80\xbfWALL\xf0\x01\x01\xf8\x01b\x80\x02\xfd\x98\xa8\xdd\x03\x90\x02\x01\xd0\x02\r\xd8\x023\xe0\x02\xc1\xb7\xf8\xb1\x03'
        yout_list = [yout1,yout2,yout3,yout4,yout5,yout6,yout7,yout8,yout9,yout10,yout11,yout12,yout14,yout15,yout16,yout17,yout18,yout19,yout20,yout21,yout22,yout23,yout24,yout25,yout26,yout27,yout28,yout29,yout30,yout31,yout32,yout33,yout34,yout35,yout36,yout37,yout38,yout39,yout40,yout41,yout42,yout43,yout44,yout45,yout46,yout47,yout48,yout49,yout50,yout51]
        global cmodeinfo
        cmodeinfo = True
        global cmodeloop
        cmodeloop = False        
        global random
        random = False
        global full
        global exitpacket
        global enterpacket
        exitpacket = b''
        enterpacket = b''
        idinfo = True
        global visible_ret
        global fivesq
        kema = False
        activation = True
        global roba
        packet0300 = True
        roba = 1
        stat = True
        global viback
        viback = False
        restartsock = False
        global startspammsg
        startspammsg = False
        global lg_room
        lg_room = False
        global spam_invs
        spam_invs = False
        global fivesq
        fivesq = False
        global increaseL
        increaseL = False
        global inv_ret
        inv_ret = False
        global visible_ret
        visible_ret = False
        global add_yout
        add_yout = False
        global msg1
        msg1 = False
        while True:
            global spamsg
            def spamsg(value):
                global startspammsg
                startspammsg = value
                return startspammsg		   
            global spam_invitations
            def spam_invitations(value3):
                global spam_invs
                spam_invs = value3
                return spam_invs
            global level_increase
            def level_increase(value6):
                global increaseL
                increaseL = value6
                return increaseL
            global youtubers
            def youtubers(value42):
                global add_yout
                add_yout = value42
                return add_yout
            r, w, e = select.select([client, remote], [], [])
            global start
            global full
            global hidd
            if client in r or remote in r:
                global serversocket
                global remotesockett
                global clientsockett
                if client in r:
                    global team
                    global teams
                    global solo
                    global packett1
                    global levelplus
                    global packett
                    global spyN
                    global spy
                    global visback
                    global vispacket
                    global dataC
                    dataC = client.recv(999999)
                    global hide
                    hide =False
                    global id_view
                    global rolp
                    global mess
                    global cheak
                    cheak = False
                    global comand
                    global resasa
                    global msgs
                    global recordmode
                    if '0e15' in dataC.hex()[0:4] and len(dataC.hex()) == 44:
                        exitpacket = dataC
                    if '0e15' in dataC.hex()[0:4] and len(dataC.hex()) > 80 and len(dataC.hex()) < 180:
                        enterpacket = dataC
                        room = remote
                    if '0515' in dataC.hex()[0:4]:
                        f=12
                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141:
                        hide = True
                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141  :
                    	self.data_join=dataC
                    	packett = dataC
                    	teams = remote
                    	print(P)
 
                    	global miki
                    	miki = remote
                    	global robou
                    	robou = dataC
                    if '0515' in dataC.hex()[0:4] and len(dataC.hex()) < 50:
                       self.data_back=dataC
                       packett1 = dataC
                       team = remote                                 
                    if '0515' in dataC.hex()[0:4] and 700 < len(dataC.hex()) < 1100:
                       solo = dataC          
                       print("nise")          
                    if msgs ==True:
                        if '1215' in dataC.hex()[0:4]:
                            for i in range(10):
                                remote.send(dataC)
                            global spprspm
                            b = threading.Thread(target=spprspm, args=(remote,dataC))
                            b.start()
                    if port == 39698:
                            levelplus = remote
                            clientC = client
                            clientM = remote
                    if port == 39801:
                             remoteC = client                  
                    if  "39698" in str(remote) :
                    	self.op = remote
                    if '0515' in dataC.hex()[0:4] or '23.90.158.22' in str(remote) :
                        op = remote
                    if remote.send(dataC) <= 0:
                        break
                if remote in r:
                    global hidr
                    global cliee
                    global lag
                    global newdataS
                    global newdataSofspam
                    global newdataSoffspam
                    global clieee
                    global backto
                    global actcode
                    global returntoroom
                    global newbackdataS
                    global getin
                    global spaminv
                    global spammsg
                    global preventlag
                    global sqlag                    
                    global ingroup5
                    global group5
                    global invite
                    global roomp
                    global number
                    global acctive
                    global invtoroom
                    global msgact
                    global lagscript
                    global lagmsg
                    global stoplag
                    global stopmsg
                    global cpy
                    global back                   
                    global full
                    global listt
                    global C
                    global istarted
                    global gameplayed
                    global packet
                    global socktion
                    global increase
                    global roomp
                    global roomretst
                    global number
                    global invtoroom
                    global invtoroompacket
                    global snv
                    global newdataS2
                    global packet1
                    dataS = remote.recv(999999)
                    if '0e00' in dataS.hex()[:4] and '0e15' in dataC.hex()[:4] and preventlag == True:
                            pass
                    else:
                        if increaseL == True:
                            threading.Thread(target=xmodz,args=(levelplus,)).start()
                            increaseL = False
                        if full == True:               
                            full = False
                        if '0e15' in dataC.hex()[:4] and returntoroom ==True:
                            remote.send(lag)
                            returntoroom =False
                            clieee = remote
                            st =False
                        if '0e15' in dataC.hex()[:4]:
                            remotesockett = remote
                            clientsockett = client
                        if '0e15' in dataC.hex()[0:4] and 75 < len(dataC.hex()) < 180:
                            clieee = remote
                            lag = dataC
                        if lg_room == True:
                            preventlag =True
                            threading.Thread(target=lagroom,args=(clieee,lag)).start()
                            restartsock = True
                        if lg_room == False:
                            preventlag = False
                            if restartsock == True:
                                try:
                                    remotesockett.close()
                                    clientsockett.close()
                                except:
                                    pass
                                restartsock = False
                        try:
                            if '1200' in dataS.hex()[0:4] and b'/info' in dataS and comand == True:
                                backto = client
                                newbackdataS = dataS.hex()
                                full = True
                        except:
                            pass
                        if cmodeloop==True:
                            threading.Thread(target=crazymode,args=(teams,solo,packett)).start()
                        if cmode == False:
                            cmodeloop = False                            
                        if  port == 39698:
                            invite = client
                            snv = remote
                        if startspammsg == True:
                           recordmode = True
                        if startspammsg == False:
                            statues = False
                        if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 900 and spam_invs == True :
                                try:
                                    for i in range(200):
                                        try:
                                            remote.send(dataC)
                                        except:
                                            pass
                                        for k in range(1):
                                                time.sleep(0.001)
                                    b = False
                                    spam_invs = False
                                    remote.close()
                                    client.close()
                                except:
                                    b = False
                                    spam_invs = False
                                    remote.close()
                                    client.close()                
                        
                        if '0e00' in dataS.hex()[0:4]:
                           for i in range(10):
                               pattern = fr"x0{str(i)}(\d+)Z"
                               match = re.search(pattern, str(dataS))
                               if match:
                                   number = match.group(1)
                                   global romcode
                                   romcode = number
                                   break
                           if match:
                               pass
                           else:
                               if "OPENATTRIBUTESEXT" in str(dataS):
                                    pass
                        if spam_invs == True:
                                b = True

                                

##################################



                        if b"/like" in dataS and comand ==True:

                             
                            text = str(bytes.fromhex(dataS.hex()))
                            pattern = r'/likkke(\d+)'
                            match = re.search(pattern, text)
                            number = match.group(1)
                            like = likes_plus(number)
                            BesTo_msg(f"""[b][c][00FFFF]{like}""", dataS.hex(), client)                               


################################ 




                        if b"/spammm" in dataS and comand ==True:
                             
                            text = str(bytes.fromhex(dataS.hex()))
                            pattern = r'/spam(\d+)'
                            match = re.search(pattern, text)
                            number = match.group(1)
                            spam = send_spam(number)
                            BesTo_msg(f"""[b][c][FFFF00]\n\n- {spam} \n\n""", dataS.hex(), client)        
                            
                            
                            
################################                            
                        
                        if b"/pc" in dataS and comand == True:
                        
                            
                            
                            text = str(bytes.fromhex(dataS.hex()))
                            pattern = r'/ppppc(\d+)'
                            match = re.search(pattern, text)
                            number = match.group(1)
                            my_id = dataS.hex()[12:22]
                            id_admin = "8fb5ff9509"
                            #دخول اي فريق
                            if len(id_admin) > 8:
                                name = getname(number)
                                hex_name = name.encode('utf-8').hex()
                                hex_name = adjust_text_length(hex_name)
                                clientC.send(bytes.fromhex(f'05000003ff08{id}100520062af20708{id_admin}12024d451801200332cc0408{id_admin}12135b6564303930395d50454741e2808f535553201a024d4520a6e38baa0628443087cbd13038324218e0f38766e796a3618994e660f39ae061e5b7d064bfb8ce64480150ce01588e0c60f5d7d0ad0368c2dc8dae037a05d7d0cab00382012b08b3daf1eb041211d8b2d98ad988d98ad986d983d983e29cbf180620b687d4f0042a0808c49d85f30410038801ed89c5b00392010b0107090a0b1216191a20239801cd01a00111a80185fff5b103c00101c80101d001bace89af03e80101880203920207c20500a606e532aa020a080110c03e18f0602002aa0205080210b232aa0205080310e432aa020a080f10918a0118a09c01aa0205081710e750aa0205081810b768aa0205081a10da74aa0206081b10918a01aa0206081c10958c01aa02050820108b79aa0205082110eb7aaa0205082210a275aa0206082310dc8701aa0205082b10f476aa0205083110f476aa0206083910918a01aa0206083d10918a01aa0206084110918a01aa0205084910e432aa0205084d10e432aa0206083410918a01aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea02520a4c68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f3237373631373532363237343633352f706963747572653f77696474683d313630266865696768743d31363010011801f202090887cab5ee0110870a8a030808021003180528019203009803f3e78ea30ba20315e298afd986d8a7d8acd988d986d98ae298afe29c9432d00208{id}120b{hex_name}1a024d452096ed8baa0628043089cbd13038324214fa96e660b599a361c19de061aab9ce64abb9ce64480150c90158e80792010601090a1219209801c901c00101c80101e80101880204920206ee07ce010000aa0208080110ff34188064aa020b080f10fd3218b086012001aa0205080210e432aa0205081810fd32aa0205081a10fd32aa0205081c10fd32aa0205082010fd32aa0205082210fd32aa0205082110fd32aa0205081710e432aa0205082310fd32aa0205082b10fd32aa0205083110fd32aa0205083910fd32aa0205083d10fd32aa0205084110fd32aa0205084910d836aa0205084d10e432aa0205081b10fd32aa0205083410fd32aa0205082810e432aa0205082910e432c2022112041a0201041a090848120501040506071a0508501201631a0508511201652200ea0204100118018a03009203003a0101400150016801721e313639383838363035353130343733333939355f6a67386c37333431646688018090aefec3978fef17a20100b001e001ea010449444331'))
                              
                                
                                    
 #################################
                                                                
                                                                            
                                                                                                          
                        if b"/5s" in dataS and comand == True:
                            
                            id = dataS.hex()[12:22]
                            clientC.send(bytes.fromhex(f"05000001ff08{id}1005203a2af20308{id}12024d451801200432f70208{id}1209424c52585f4d6f642b1a024d4520d78aa5b40628023085cbd1303832421880c38566fa96e660c19de061d998a36180a89763aab9ce64480150c90158e80792010801090a12191a1e209801c901c00101e801018802039202029603aa0208080110e43218807daa0207080f10e4322001aa0205080210e432aa0205081810e432aa0205081a10e432aa0205081c10e432aa0205082010e432aa0205082210e432aa0205082110e432aa0205081710e432aa0205082310e432aa0205082b10e432aa0205083110e432aa0205083910e432aa0205083d10e432aa0205084110e432aa0205084910e432aa0205084d10e432aa0205081b10e432aa0205083410e432aa0205082810e432aa0205082910e432c2022812041a0201041a0508501201631a060851120265661a0f0848120b0104050607f1a802f4a8022200ea0204100118018a03009203009803b7919db30ba20319c2b27854e19687e197a95fe191ade192aae197a95945e19687e20301523a011a403e50056801721e313732303237323231313638373535353930315f736f3278687a61366e347801820103303b30880180e0aecdacceba8e19a20100b00114ea010449444332fa011e313732303237323231313638373535383330335f71356f79736b3934716d"))
                            
                                     
                                              
                                         
##################################
                                          
                                                                                      
                        if b'/frrr' in dataS and comand ==True:    
                            mess = True                            
                            x = 0
                            if len(dataS.hex())<=30:
                                hide = True
                            if len(dataS.hex())>=25:
                                packet1 = dataS
                                global packetd
                                liner = client                                
                                spyN = dataS
                                              





#################################



                        
                        if b"/6s" in dataS and comand == True:
                            
                            id = dataS.hex()[12:22]
                            clientC.send(bytes.fromhex(f"050000032708{id}100520082a9a0608dbdcd7cb251a910608{id}12024d4518012005329d0508{id}121ee28094cd9ecd9fcd9ee29885efbcb6efbca5efbcaeefbcafefbcade385a41a024d4520ebdd88b90628363087cbd1303832421880c38566949be061e1cea561b793e66080a89763e5bfce64480150d60158991468b7db8dae037a05ab93c5b00382011f08d1daf1eb0412054f75656973180420d487d4f0042a0808cc9d85f304100392010b0107090a0b12191a1e20229801db01a0014fc00101d001ada48aaf03e80101880203920208c205d628ae2db202aa02050801109c44aa0208080210ea3018c413aa0208080f10d836188827aa0205081710bd33aa0205082b10e432aa0205083910a070aa0205083d10c16faa02050849108439aa0205081810d836aa0205081a10d836aa0205081c10d836aa0205082010d836aa0205082210d836aa0205082110d836aa0205082310d836aa0205083110e432aa0205084110d836aa0205084d10e432aa0205081b10d836aa0205083410d836aa0205082810e432aa0205082910e432c202cd0112041a0201041a730848121301040506070203f1a802f4a802f2a802f3a8021a0b080110031886032086ac021a0b0802100418810420c59a081a0b0803100418da0620ecb4051a06080520f5ec021a0d08f1a802100318b80320def0041a0d08f2a802100318bc0520d0e90a1a0d08f3a802100318ef032092c9051a1208501201631a0b0863100e188f0420eeba0d1a1b0851120265661a09086520a6910128e7021a08086620822d289e05221f121d65ed0e890ed9049103f503ad02f90abd05e907a1068507cd08950ab109d802a6a38daf03ea020410011801f202080885cab5ee01105c8a0300920300980398e0b3af0ba20319efbca334e385a4eaa884e385a4efbcb4efbca5efbca1efbcada80368b00301c2030a081c100f180320052801e203014fea03003a011a403e50056801721e313733303239333438313635343436323834305f6c646a72387477723378880180909beaf3d18fd919a20100b001e201ea010449444331fa011e313733303239333438313635343436363239355f6f747735637831756c6d050000031e08{id}1005203a2a910608{id}12024d4518012005329d0508{id}121ee28094cd9ecd9fcd9ee29885efbcb6efbca5efbcaeefbcafefbcade385a41a024d4520ebdd88b90628363087cbd1303832421880c38566949be061e1cea561b793e66080a89763e5bfce64480150d60158991468b7db8dae037a05ab93c5b00382011f08d1daf1eb0412054f75656973180420d487d4f0042a0808cc9d85f304100392010b0107090a0b12191a1e20229801db01a0014fc00101d001ada48aaf03e80101880203920208c205d628ae2db202aa02050801109c44aa0208080210ea3018c413aa0208080f10d836188827aa0205081710bd33aa0205082b10e432aa0205083910a070aa0205083d10c16faa02050849108439aa0205081810d836aa0205081a10d836aa0205081c10d836aa0205082010d836aa0205082210d836aa0205082110d836aa0205082310d836aa0205083110e432aa0205084110d836aa0205084d10e432aa0205081b10d836aa0205083410d836aa0205082810e432aa0205082910e432c202cd0112041a0201041a730848121301040506070203f1a802f4a802f2a802f3a8021a0b080110031886032086ac021a0b0802100418810420c59a081a0b0803100418da0620ecb4051a06080520f5ec021a0d08f1a802100318b80320def0041a0d08f2a802100318bc0520d0e90a1a0d08f3a802100318ef032092c9051a1208501201631a0b0863100e188f0420eeba0d1a1b0851120265661a09086520a6910128e7021a08086620822d289e05221f121d65ed0e890ed9049103f503ad02f90abd05e907a1068507cd08950ab109d802a6a38daf03ea020410011801f202080885cab5ee01105c8a0300920300980398e0b3af0ba20319efbca334e385a4eaa884e385a4efbcb4efbca5efbca1efbcada80368b00301c2030a081c100f180320052801e203014fea03003a011a403e50056801721e313733303239333438313635343436323834305f6c646a72387477723378880180909beaf3d18fd919a20100b001e201ea010449444331fa011e313733303239333438313635343436363239355f6f747735637831756c6d"))

                        



                            
##################################


                        
                        if b"/ms" in dataS and comand == False:
                            msgs =False
                        if b"#ms" in dataS and comand == False:
                            msgs =False
                        if b"/inv" in dataS and comand == True:     
                            spam_invs =True
                        if b"#inv" in dataS and comand == True:
                            spam_invs =False
                            

                            
                            
#################################                              
                        
                                
                                
                        if b'/gold' in dataS and comand ==True:
                            
                            
                            
                            id = dataS.hex()[12:22]
                            clientC.send(bytes.fromhex(f"080000001308{id}100820022a0708a6b10318fa01"))
                            
 
 


##################################

                                          
                                                                    
                        if b'/dis' in dataS and comand ==True:
                            
                            
                            id = dataS.hex()[12:22]
                            clientC.send(bytes.fromhex(f"080000001308{id}100820022a0708a6b10318fa01"))                        
 
                                                       
#################################

                                  	
                        if b'@Gr' in dataS:
                            mess = False
                            id = dataplus[12:22]
                            dor = "120000083408*101220022aa71008*10*22890f5b62d98c5d5b63d98f5d5b666666666666d98f5d5b2b5d20d8a7d984d985d8b9d984d988d985d8a7d8aa0a0a5b626430363036d98f5dd985d8b9d984d988d985d8a7d8aa20d985d8aad982d8afd985d8a920d8b9d98620d984d8a7d8b9d8a80a5b666666666666d98f5d46442b2b69640a5b656430393039d98b5dd985d8b9d984d988d985d8a7d8aa20d8b9d8a7d985d8a920d8b9d98620d984d8a7d8b9d8a80a5b666666666666d98f5d4644404069640a5b623334663466d98f5dd985d8b9d984d988d985d8a7d8aa20d8aad8b5d986d98ad98120d984d8a7d8b9d8a80a5b666666666666d98f5d46443a3a69640a5b663031383531d98c5dd985d8b9d984d988d985d8a7d8aa20d8b1d8a7d8a8d8b7d8a920d984d8a7d8b9d8a8200a5b666666666666d98f5d46443f3f69640a5b643937313731d98f5dd8b9d8b1d8b620d8a8d8a7d98ad98820d984d8a7d8b9d8a80a5b666666666666d98f5d46443d3d69640a5b663061616161d98f5dd985d8b9d984d988d985d8a7d8aa20d8add8b3d8a7d8b3d8a920d8b9d98620d984d8a7d8b9d8a80a5b666666666666d98f5d406d790a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d985d8acd985d988d8b9d8a90a0a5b626461323036d98c5d3520d8a3d8b4d8aed8a7d8b520d8a8d8a7d984d985d8acd985d988d8b9d8a90a5b666666666666d98f5d404644350a5b656463663231d9925d3420d8a3d8b4d8aed8a7d8b520d8a8d8a7d984d985d8acd985d988d8b9d8a90a5b666666666666d98f5d404644340a5b663265303739d98f5d3320d8a3d8b4d8aed8a7d8b520d8a8d8a7d984d985d8acd985d988d8b9d8a90a5b666666666666d98f5d404644330a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8a7d8b5d8afd982d8a7d8a1200a0a5b656436383231d98f5dd8a5d8b6d8a7d981d8a920d8a7d984d98ad8aad98ad988d8a8d8b1d8b220d984d984d8a3d8b5d8afd982d8a7d8a10a5b666666666666d98f5d404644594f540a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8b1d982d8b5d8a7d8aa200a0a5b316239313063d98c5dd8a7d984d8add8b5d988d98420d8b9d984d98920d8b1d982d8b5d8a7d8aa0a5b666666666666d98f5d40464454780a5b343666663265d98f5dd8a5d8acd8b9d98420d8a7d98a20d984d8a7d8b9d8a820d98ad8b1d982d8b50a5b666666666666d98f5d40464452782f2f69640a5b396465363137d98c5dd984d8a7d8b9d8a820d8a7d8aed8b120d98ad982d984d8af20d8b1d982d8b5d8a7d8aad9830a5b666666666666d98f5d40464443782f2f69640a5b383065643737d98f5dd982d8a7d8a6d985d8a920d8b1d982d8b5d8a7d8aa0a5b666666666666d98f5d404644544c530a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8b3d8a8d8a7d9850a0a5b626231616462d98c5dd8b3d8a8d8a7d98520d8afd8b9d988d8a7d8aa200a5b666666666666d98f5d404644490a5b643436336562d98c5dd8b3d8a8d8a7d98520d8b1d8b3d8a7d8a6d9840a5b666666666666d98f5d404644530a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8b3d983d988d8a7d8afd8a7d8aa0a0a5b323262356436d98f5dd8acd8b9d98420d986d981d8b3d98320d985d8aed981d98a20d8a8d8a7d984d8b3d983d988d8a7d8af0a5b666666666666d98f5d404644590a5b313866666666d98c5dd8a7d984d8b9d988d8afd8a920d984d8a2d8aed8b120d8b3d983d988d8a7d8af20d8b8d8a7d987d8b10a5b666666666666d98f5d404644420a5b366664396365d98f5dd985d986d8b920d8b7d8b1d8afd98320d985d98620d8b3d983d988d8a7d8af0a5b666666666666d98f5d4046445a460a5b613765386532d98c5dd8a5d8b6d8a7d981d8a920d8b4d8aed8b520d984d984d8b3d983d988d8a7d8af0a5b666666666666d98f5d404641442f2f69640a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d5b2b5d20d8a7d984d8b1d988d985d8a7d8aa200a0a5b656233323135d98c5dd985d986d8b920d8b7d8b1d8afd98320d985d98620d8a7d984d8b1d988d985200a5b666666666666d98f5d4046444e520a5b663236653561d98c5dd8b9d8b1d8b620d983d984d985d8a920d8b3d8b120d8a7d984d8b1d988d9850a5b666666666666d98f5d40464450530a5b656432313931d98c5d5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f0a0a2020202020202020205b666666666666d98f5d205b2b5d20d8a7d984d985d982d8a8d8b1d8a9200a0a5b646231363136d98f5dd985d982d8a8d8b1d8a920d984d8a3d98a20d8b4d8aed8b520d8aad8b1d98ad8af200a5b666666666666d98f5d2040464d5554452f2f696428fcafe1af064a1f0a095a45452d544f4f4c531086db8dae0320c90142094e45575a4552424f545202656e6a600a5a68747470733a2f2f6c68332e676f6f676c6575736572636f6e74656e742e636f6d2f612f414367386f634b5930454f6b57703362383679524258466c613967704264734655684d5f724f454b393775424e46532d3d7339362d63100118017200"
                            raks = dor.replace('*', id)
                            MainC.send(bytes.fromhex(raks))
                            
                            
                            
#################################



                            
                        if b'/back' in dataS:
                            teams.send(packett)
                            
 
                                                           
                            
 ################################
 
 
                                                                     
                        
                        if b"/yt" in dataS:
   
                            
                            
                            add_yout =True
                            
                            
                            
##################################


                        if b"/spy" in dataS:
                            pack = dataS.hex() 
                            
                            
                            
                            clientC.send(bytes.fromhex("0503000001d01fb578313150905babcef51dd24ed75fd0a24b024bd1429646114bc22e604afd35a96fbc48710b2d9cfec4378287ec829e33a78608fd2dd138d4d24a19c00fbfdc9f15c77ff86d638b34de95bd886e3075e82d3f4a3888f9b6943463022c43fb90e229f0eaf8a788f6f766d891d99eb2c37b277144923212810b3c80d1c521790154ed270f5241adc136f2a22816e0bc84fcaf79386b27559de966aa788c184d35bbbfaa03a5f08746f8db0e73b2c91ec4515d61f689a0cad30a7cbd6c325151e879dabc43d506b3240abe41bc0d6b4416c18f68ef4af2d04c381be6bf586f6b25727c0c85c03a579137e4a6c602ef6d833dabdab3eba3a5266e5a4731fbfb1720b60f124cd8fd4fa26cc7a9fb6e0a218d8809f57b204d22fa97520aeb99007c7b71c709e53ecc688c9963e0786909152fa93f06dc93085468dae34e1609f33f7dee228fb058c6efd6846b50ac54db0aebb8f5bc2f6751f9e2886dbab41cbaf5a1d8cd88e6c13a2a2a56b613a2d32179dc3f781493a5027322ac0cb1a2d3c79d49fb12ed26230e1561df43d315a27be17b5debdba757803305252b5443f3d77cd319dde9c49a72c636d93d02bdd9597168f378aa6e41d0fd545abf8bc0883f3dac11ea27166683c7111a0f329bf6b6a5"))


                            
################################ 


                            
                        
                        if b"/spyrom" in dataS:
                        
                            op.send(b"\x0e\x15\x00\x00\x00P\xd6\xd5\x19\x00+\xdc\xc6M\xe8\xa4,\x1a\xae\xdf\\:\xaa\xcf|\xe6\x94\xef\xbf\xc1\xf1\x1f\x02h\t\xb6%\xe7\x93aM\xd1?\xfa8\xee\xccUO\xf3 \xa6\x1b\x8a\xc6\x96\x99\xa8\xeb^\xda\xb7;9\xe9\xd9\x10zP\xd5\xe0\x83\xa2\xbc\x8c\x01\xfb\xadd\xdb\xcek\x85\x81\xcdP")
                                               

                            ################################





                        if b"/A1" in dataS and comand == True:    
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1088b3bbb1032a0608*"                            
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))              
                        if b"/A2" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1098fbb8b1032a0608*"                            
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A3" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109bfbb8b1032a0608*"                            
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A4" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10d2c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A5" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10dcc2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A6" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10bbfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A7" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109284bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))  
                        if b"/A8" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109cfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A9" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10aefcbab1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/E1" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10fffab8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/E2" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10ff8bbbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/E3" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1095fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/E4" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*108bfbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/E5" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10edbabbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/E6" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10a2fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/E7" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*1084fbb8b1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A10" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10b9cabbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A11" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10ca9bbbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A12" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109e84bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A13" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*109684bbb1032a0608*" #10a5d2bbb1032a0608
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A14" in dataS and comand == True:
                            id = dataS.hex()[12:22]
                            dor = "050000002008*100520162a1408*10d6c2bbb1032a0608*"
                            raks = dor.replace('*', id)                                 
                            clientC.send(bytes.fromhex(raks))              
                        if b"/A15" in dataS and comand == True: 
                            id = dataS.hex()[12:22]                                    
                            dor = "050000002008*100520162a1408*10a1d2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A16" in dataS and comand == True: 
                            id = dataS.hex()[12:22]                                    
                            dor = "050000002008*100520162a1408*10a3d2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A17" in dataS and comand == True: 
                            id = dataS.hex()[12:22]                                    
                            dor = "050000002008*100520162a1408*10a2d2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))           
                        if b"/A18" in dataS and comand == True: 
                            id = dataS.hex()[12:22]                                    
                            dor = "050000002008*100520162a1408*10a5d2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))
                        if b"/A19" in dataS and comand == True: 
                            id = dataS.hex()[12:22]                                   
                            dor = "050000002008*100520162a1408*10d7c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))              
                        if b"/A20" in dataS and comand == True: 
                            id = dataS.hex()[12:22]                                   
                            dor = "050000002008*100520162a1408*10c1cabbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks))              
                        if b"/E8" in dataS and comand == True: 
                            id = dataS.hex()[12:22]                                   
                            dor = "050000002008*100520162a1408*10d8c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            clientC.send(bytes.fromhex(raks)) 
                            
                                         
                                                      ###############################
                                                      
                                                                                
                        if b"/dm" in dataS and comand == True:
                                newdataS2 = dataS.hex()
                                getin = client
                                id = dataS.hex()[12:22]                                
                                dor = "080000001608a29b81aa22100820022a0a08e7be0110b24f18c801*"
                                raks = dor.replace('*', id)
                                clientC.send(bytes.fromhex(raks)) 
 
                                
                                                                                              
##################################


                                         
                        if b"/sev" in dataS and comand == True:
                            id = dataS.hex()[12:22]                                    
                            dor = "050000002008*100520162a1408*10d7c2bbb1032a0608*"
                            raks = dor.replace('*', id)
                            time.sleep(0.8)    
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                            clientC.send(bytes.fromhex(raks)) 
                            time.sleep(0.8)
                       
                            
  
                                                                        
                                          


##################################


                                          
                                                           
                        
                        if '0e00' in dataS.hex()[0:4] and roomretst == True and "http" in str(dataS):
                            invtoroom = client
                            invtoroompacket = dataS
                        try:
                            pass                                               
                        except:
                            pass
                        if msg1 ==True:
                                    random_variable = random.choice([ms11, ms12, ms13])
                                    remote.send(random_variable)
                        if add_yout == True:
                            add_yout = False
                            from time import sleep
                            try:
                                for h in yout_list:
                                    clientC.send(h)
                                    sleep(0.2)
                            except:
                                pass
                        if b'/LAG FREE' in dataS:
                            while True:
                                add_yout = True
                                time.sleep(5)
                                ################################                                                     	      	      	      	      	     	      	      	
                        if b'/help' in dataS:
                            BesTo_msg(f"""[FF0000][i][b][c]\n\n- Welcome To XTZ BOT PRO !\n\n""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][FFFF00]\n- مميزات واوامر البوت :\n""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< خمسة اشخاص في الفريق  :  [FFFFFF]\n\n- /5sㅤㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]<  ستة اشخاص في الفريق  :  [FFFFFF]\n\n- /6sㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]<  زيادة 100 لايك  :  [FFFFFF]\n\n- /like[id]ㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< سبام طلبات صداقه : [FFFFFF]\n\n- /spam[id]ㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< صديق الوهمي : [FFFFFF]\n\n- /frㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< لوغو البسي : [FFFFFF]\n\n- /pc[id]ㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< جواهر وهمية  : [FFFFFF]\n\n- /dmㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< غولد وهمي  :  [FFFFFF]\n\n- /goldㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< سبام طلبات الانضمام :  [FFFFFF]\n\n  - /invㅤㅤㅤ""", dataS.hex(), client)
                            
                            BesTo_msg(f"""[b][c][00FFFF]< الاختفاء لاعب في الفريق : [FFFFFF]\n\n- /spyㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< الاختفاء لاعب في الروم : [FFFFFF]\n\n- /spyromㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< رقصات مميزة : [FFFFFF]\n\n- /A1 --> /A20ㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< رقصات اسلحة :  [FFFFFF]\n\n- /E1 --> /E8ㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< سبام رقصات :  [FFFFFF]\n\n- /sevㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< اضافة يوتيوبر للاصدقاء : [FFFFFF]\n\n- /ytㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[b][c][00FFFF]< مطورين البوت :  [FFFFFF]\n\n- /devㅤㅤㅤㅤ""", dataS.hex(), client)
                            BesTo_msg(f"""[FF0000][i][b][c]\n\n- Dev By : @F_O_U_B_I_A\n\n""", dataS.hex(), client)
                                                                               	             	
                         	
#################################
                                                   

 
                        if b'/dev' in dataS:
                            BesTo_msg(f"""[b][c]- Developer Bot : \n\n\n[00FFFF]-  Ig : @F_O_U_B_I_A""", dataS.hex(), client)
                                            
                                                ################################                                                                                                                                                                                             
                        
                        if b"/emmmo" in dataS:
                                BesTo_msg(f"""[b][i][c][FFFF00]- رقصات مميزة\n\n[00FF00]- تم تفعيل""", dataS.hex(), client)
                                BesTo_msg(f"""[b][i][c][00FF00]- طريقة الاستخدام :\n\n /A1  -->  /A20""", dataS.hex(), client)
                        
                        if b"/evvvo" in dataS:
                                BesTo_msg(f"""[b][c][FFFF00]- رقصات اسلحة\n\n[00FF00]- تم تفعيل""", dataS.hex(), client)
                                BesTo_msg(f"""[b][c][FF0000]- طريقة الاستخدام :\n\n /E1  -->  /E8""", dataS.hex(), client)                                                                                                                                                                                                                                                  ################################
                                                  
                                                                  
                        if b"/Runnnn" in dataS:
                        	BesTo_msg(f"""[F433FF][i][b][c]\n\n- Welcome To Rbgx Bot !\n\n""", dataS.hex(), client)
                        	BesTo_msg(f"""[b][c]- القائمة الاولى : \n\n[00FFFF] ¦ صديق وهمي  -  /fr \n ¦ سبام طلبات الانضمام  - /inv\n ¦ خمسة في الفريق - /5s\n ¦ ستة اشخاص في الفريق  - /6s""", dataS.hex(), client)
                        	BesTo_msg(f"""[b][c]- القائمة التانية : \n\n[FFFF00] ¦ تصفير الجواهر - /dis\n ¦ جواهر وهمية - /dm\n ¦ يوتيوبر اصدقائك  -  /yout\n ¦ اختفاء لاعب  -  /spy\n ¦ سبام طلبات صداقه - /spam[id]""", dataS.hex(), client)
                        	BesTo_msg(f"""[b][c]- القائمة الثالثة : \n\n[00FF00] ¦ رقصات مميزة  -  /emo\n ¦ رقصات اسلحة مطورة -  /evo\n ¦ سبام رقصات -  /sev\n ¦ زيادة 100 لايك  - /like[id]""", dataS.hex(), client)
                        	BesTo_msg(f"""[b][c]- القائمة الرابعة : \n\n[FF0000] ¦ لوغو البيسي - /pc[id]\n ¦ غولد وهمي - /gold\n ¦ اختفاء لاعب في الروم-  /spyrom\n ¦ مطورين البوت  -  /dev""", dataS.hex(), client)
                        	BesTo_msg(f"""[i][b][c][b][c] - البوت شغال يمكنك استخدام \n\nكل المميزات المعروضة امامك """, dataS.hex(), client)   
 
                                 
                            
################################                            


                        
                        	
                        	                                                        
                        if b'/rettt' in dataS and '1200' in dataS.hex()[0:4]:
                           clieee.send(lag)
                        if client.send(dataS) <= 0:
                            break      
    def foxy( self , data_join):
        global back
        while back==True:
            self.op.send(data_join)
            time.sleep(9999.0)                                    
def rb_V5():
        Proxy().runs('127.0.0.1',3000)        
rb_V5()
