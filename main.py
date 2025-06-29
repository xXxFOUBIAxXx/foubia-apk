import socket
import select
import requests
import threading
import re
import time
import struct
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Ghost = False
back = False
enc_client_id = None
inviteD = False
SOCKS_VERSION = 5
invit_spam = False

class Proxy:
    def __init__(self):
        self.username = "1"
        self.password = "1"
        self.website = "http://xtz-encrypt-apk.vercel.app/Encrypt?Uid={id}"
        

    def spam__invite(self, data, remote):
        global invit_spam
        while invit_spam:
            try:
                for _ in range(5):
                    remote.send(data)
                    time.sleep(0.04)
                time.sleep(0.2)
            except:
                pass

    def fake_friend(self, client, id: str):
        if len(id) == 8:
            packet = '060000007708d4d7faba1d100620022a6b08cec2f1051a1b5b3030464630305d2b2b2020202047484f53545b3030464630305d32024d454049b00101b801e807d801d4d8d0ad03e001b2dd8dae03ea011eefbca8efbca5efbcb2efbcafefbcb3efbca8efbca9efbcadefbca1efa3bf8002fd98a8dd03900201d00201'
            packet = re.sub(r'cec2f105', id, packet)
            client.send(bytes.fromhex(packet))
        elif len(id) == 10:
            packet = '060000006f08d4d7faba1d100620022a6308fb9db9ae061a1c5b3030464630305d2b2be385a447484f535420205b3030464630305d32024d454040b00113b801e71cd801d4d8d0ad03e00191db8dae03ea010a5a45522d49534b494e47f00101f801911a8002fd98a8dd03900201d0020ad80221'
            packet = re.sub(r'fb9db9ae06', id, packet)
            client.send(bytes.fromhex(packet))
        else:
            print(id)

    def Encrypt_ID(self, id):
        api_url = self.website.format(id=id)
        try:
            response = requests.get(api_url)
            if response.status_code == 200:
                return response.text
            else:
                print("&#1601;&#1588;&#1604; &#1601;&#1610; &#1580;&#1604;&#1576; &#1575;&#1604;&#1576;&#1610;&#1575;&#1606;&#1575;&#1578;. &#1585;&#1605;&#1586; &#1575;&#1604;&#1581;&#1575;&#1604;&#1577;:", response.status_code)
                return None
        except requests.RequestException as e:
            print("&#1601;&#1588;&#1604; &#1575;&#1604;&#1591;&#1604;&#1576;:", e)
            return None

    def handle_client(self, connection):
        version, nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection)
        if 2 not in set(methods):
            connection.close()
            return
        connection.sendall(bytes([SOCKS_VERSION, 2]))
        if not self.verify_credentials(connection):
            return
        version, cmd, _, address_type = connection.recv(4)
        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domain_length = connection.recv(1)[0]
            address = connection.recv(domain_length)
            address = socket.gethostbyname(address)
        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
            else:
                connection.close()
                return
            addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
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
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(connection, remote)
        connection.close()

    def gen_squad5(self):
        ent_packet = f"050000030608{self.squad_gen}100520082af90508{self.squad_gen}1af00508{self.EncryptedPlayerid}12024d451801200432f50408{self.EncryptedPlayerid}1211e385a4e1b49ce1b498e385a4e1afa4ccb81a024d4520a4fda7b40628423084cbd13042188993e660c0bcce64e796a361fb9ae061948b8866e8b6ce64480150d70158851568e4b58fae037a0a9cd2cab00392d0f2b20382012608efdaf1eb04120cd8afd98ad8b1d8acd8a7d985180720f087d4f0042a0808ca9d85f304100392010b010307090a0b12191a1e209801dd01a0017fba010b08d6f9e6a202100118d702c00101e80105f0010e880203920208ae2d8d15ba29b810aa0208080110cc3a18a01faa0208080210f02e188827aa020a080f108e781888272001aa0205081710a14faa0205081810df31aa0205081c108f31aa0205082010c430aa0205082110cb30aa0205082210dd31aa0205082b10f02eaa0205083110f02eaa0205084910f936aa0205081a108e78aa02050823108e78aa02050839108e78aa0205083d108e78aa02050841108e78aa0205084d10e432aa0205081b108e78aa02050834108e78aa0205082810e432aa0205082910e432c2026012031a01011a3f084812110104050607f1a802f4a802f2a802f3a8021a0d08f1a802100318ec0220c3ca011a0d08f2a802100318940320a3e8041a0a08f3a802100220fec2011a0508501201631a060851120265662209120765890eed0ed904d802a8a38daf03ea020410011801f2020b0883cab5ee0110b00218018a030092032a0a13080310f906180f201528f0bbacb40632024d450a13080610a50e180f200a28f0bbacb40632024d459803fdb4b4b20ba203044d454523a80368b00302b80301c203080828100118032001c20308081a100f1803200cca030a0801109b85b5b4061801ca030a080910abf6b0b4061801d003013a011a403e50056801721e313732303331393634393738313931313136365f616471383367366864717801820103303b30880180e0aee990ede78e19a20100b00114ea010449444331fa011e313732303331393634393738313931353431355f317475736c316869396a"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def invisible1(self):
        ent_packet = f"050000030d08{self.EncryptedPlayerid}1005203a2a800608{self.EncryptedPlayerid}12024d4518012005328c0508{self.EncryptedPlayerid}121ee28094cd9ecd9fcd9ee29885e29a91efbca7efbca8efbcafefbcb3efbcb41a024d4520de90ebb80628443087cbd1303832421883938866ddcea561a6c2e860f4bece64f39ae0619cb9ce64480150dc0158e21c60998fd3ad0368f4dc8dae037a05b092c5b00382012708dbdaf1eb04120d7be28886c2a9cf80c2a9c2ae7d180720e187d4f0042a0808c89d85f30410038801c2ffc4b00392010c0107090a0b120e16191a1e209801d401a0012ca80185fff5b103c00101d001b6cb8aaf03e80101880203920207c205b60969a926aa0207080110dc3d2004aa0205080210a038aa0208080f10d63618904eaa0205081710aa51aa02050818108242aa0205081a10b836aa0205081b10d636aa0205081c109a42aa0205082010da3daa0205082110f02eaa0205082210c935aa0205082310eb2faa0205082b10862faa0205083110f02eaa0205083910f95daa0205084910fa33aa0205083d10d636aa0205084110d636aa0205084d10e432aa0205083410d636aa0205082810e432aa0205082910e432c202a90112031a01011a6f0848121001040506070203f1a802f4a802f2a8021a0b0806100118880420a48e1c1a0b0801100318810320f0a0031a0b08021004118fb0620e7f4041a0b0803100418ef0520ddbb0b1a0b0807100118ff0120c589051a0d08f1a802100318cd0320dc81051a0908f3a802100120b14d1a1208501201631a0b0863100a18940720d3d90c1a100851120265661a08086620c81528d407220b120965890eed0ed904ad02d802a8a38daf03ea020410011801f202090882cab5ee0110b0088a0300920300a80366b00301c2030a081c100f180220022801ca030a0806108b99fab8061801ca030a0802108b99fab8061801e203014fea03003a011a403e50056801721e313732393830383339323636343834313338335f6d7531726c6835303164880180909baef882c1d519a20100b001e201ea010449444332fa011e313732393830383339323636343834343134335f6a336d347a7972303337"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def gen_squad6(self):
        ent_packet = f"050000030d08{self.EncryptedPlayerid}1005203a2a800608{self.EncryptedPlayerid}12024d4518012005328c0508{self.EncryptedPlayerid}121ee28094cd9ecd9fcd9ee29885e29a91efbca7efbca8efbcafefbcb3efbcb41a024d4520de90ebb80628443087cbd1303832421883938866ddcea561a6c2e860f4bece64f39ae0619cb9ce64480150dc0158e21c60998fd3ad0368f4dc8dae037a05b092c5b00382012708dbdaf1eb04120d7be28886c2a9cf80c2a9c2ae7d180720e187d4f0042a0808c89d85f30410038801c2ffc4b00392010c0107090a0b120e16191a1e209801d401a0012ca80185fff5b103c00101d001b6cb8aaf03e80101880203920207c205b60969a926aa0207080110dc3d2004aa0205080210a038aa0208080f10d63618904eaa0205081710aa51aa02050818108242aa0205081a10b836aa0205081b10d636aa0205081c109a42aa0205082010da3daa0205082110f02eaa0205082210c935aa0205082310eb2faa0205082b10862faa0205083110f02eaa0205083910f95daa0205084910fa33aa0205083d10d636aa0205084110d636aa0205084d10e432aa02050834110d636aa0205082810e432aa0205082910e432c202a90112031a01011a6f0848121001040506070203f1a802f4a802f2a8021a0b0806100118880420a48e1c1a0b0801100318810320f0a0031a0b0802100418fb0620e7f4041a0b0803100418ef0520ddbb0b1a0b0807100118ff0120c589051a0d08f1a802100318cd0320dc81051a0908f3a802100120b14d1a1208501201631a0b0863100a18940720d3d90c1a100851120265661a08086620c81528d407220b120965890eed0ed904ad02d802a8a38daf03ea020410011801f202090882cab5ee0110b0088a0300920300a80366b00301c2030a081c100f180220022801ca030a0806108b99fab8061801ca030a0802108b99fab8061801e203014fea03003a011a403e50056801721e313732393830383339323636343834313338335f6d7531726c6835303164880180909baef882c1d519a20100b001e201ea010449444332fa011e313732393830383339323636343834343134335f6a336d347a7972303337"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def gen_squad8(self):
        ent_packet = f"05000004d908{self.EncryptedPlayerid}100520062acc0908{self.EncryptedPlayerid}12024d451801200332ef0408{self.EncryptedPlayerid}1221e28094cd9ecd9fcd9ee29885efbca8efbcafefbcb3efbcb3efbca1efbcadefbca51a024d4520d4f4babc0628443087cbd13038324218869be06183938866a9b7d0649cb9ce64ddcea561a6c2e860480150cf0158900d60c5d8d0ad0368f9db8dae037a05b092c5b003820121089fdaf1eb041207247b7a61796e7d180720a387d4f0042a0808c29d85f30410038801c2ffc4b00392010c010407090a0b120e16191a209801cf01a00118a80185fff5b103c00101e80101880203920208c205a92df9038a07aa0207080110e4322004aa0205080210a038aa0208080f10853218904eaa0205081710aa51aa02050818108242aa0205081a10b836aa0205081b108532aa0205081c109a42aa0205082010da3daa0205082110f02eaa0205082210c935aa0205082310eb2faa0205082b10f02eaa0205083110f02eaa0205083910f95daa0205084910fa33aa0205083d108532aa02050841108532aa0205084d10e432aa02050834108532aa0205082810f02eaa0205082910e432c202a90112031a01011a6f0848121001040506070203f1a802f4a802f2a8021a0b0806100118880420a48e1c1a0b0801100318810320f0a0031a0b0802100418fb0620e7f4041a0b0803100418ef0520ddbb0b1a0b0807100118ff0120c589051a0d08f1a802100318cd0320dc81051a0908f3a802100120b14d1a1208501201631a0b0863100a18940720d3d90c1a100851120265661a08086620c81528d407220b120965890eed0ed904ad02d802a8a38daf03ea020410011801f202090885cab5ee0110a8018a0300920300a80366c2030a081d100f180220012801e203014fea0300f2030080045f90040232e403089bc68ad21f1224efb5bcefb5afefb5bcefb5afefb5bcefb5afefb5bcefb5afefb5bcefbca8efbca5efbcb81a024d4520d9f4babc0628073087cbd13038324218ab94e660d19ce261d2c385669fbace64e996a3619ebace64480150c90158e80760868fd3ad0368c79390ae037a05b59dc5b00382011808b3daf1eb04180420b487d4f0042a0808c49d85f304100392010a0107090a120e16191a209801c901a00101c00101e80101880203920205c205000000aa0207080110e4322001aa0208080f10a63118904eaa0205081710ee32aa0205082b10f02eaa0205080210e432aa0205081810a631aa0205081a10a631aa0205081c10a631aa0205082010a631aa0205082210a631aa0205082110a631aa0205082310a631aa0205083110f02eaa0205083910a631aa0205083d10a631aa0205084110a631aa0205084910d836aa0205084d10e432aa0205081b10a631aa0205083410a631aa0205082810904eaa0205082910e432b00201c2022812041a0201041a0f0848120b0104050607f1a802f4a8021a0508501201631a060851120265662200d802c5d8a5af03ea0204100118018a03009203009803ddb6b2ab0ba2031eefbca8efbca5efbcb8e385a4e29cbfe385a4efbcb4efbca5efbca1efbcade20302452ea0300f203008004649004023a01014001500260016801721e313733373430373036303733303437383236375f74776168373565767a7688018090fbf3dcd68f8e1aa20100b001e301ea010449444332fa011e313733373430373036303733303438313336305f6172397538656a793571"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}1088b3bbb1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance2(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}1098fbb8b1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance3(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}109bfbb8b1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance4(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10d2c2bbb1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance5(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10dcc2bbb1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance6(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10bbfbb8b1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance7(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}109284bbb1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance8(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}10ff8bbbb1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance9(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408{self.EncryptedPlayerid}108bfbb8b1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance10(self):
        ent_packet = f"050000002008c1ae939607100520162a1408{self.EncryptedPlayerid}10818cbbb1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance11(self):
        ent_packet = f"050000002008c1ae939607100520162a1408{self.EncryptedPlayerid}10ca9bbbb1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance12(self):
        ent_packet = f"050000002008c1ae939607100520162a1408{self.EncryptedPlayerid}10d6c2bbb1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def Dance13(self):
        ent_packet = f"050000002008{self.EncryptedPlayerid}100520162a1408aae2cafb0210d7c2bbb1032a0608{self.EncryptedPlayerid}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def garin(self):
        ent_packet = f"050000002008c1ae939607100520162a1408{self.squad}10bdcabbb1032a0608{self.squad}"
        self.sock0500.send(bytes.fromhex(ent_packet))

    def help(self):
        ent_packet = f"120000013108{self.EncryptedPlayerid}101220022aa40208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}227be385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a45b625d5b4646303030305d20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a45a4f4449414720424f542050524f20e385a428b9f7b9bc064a380a21e28094cd9ecd9fcd9ee29885efbca8efbcafefbcb3efbcb3efbca1efbcadefbca510f9db8dae0318c5d8d0ad0320cf012885fff5b103520261726a530a4d68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f323335383432343031343430383133372f706963747572653f77696474683d313630266865696768743d313630100118017200"
        self.sock1200.send(bytes.fromhex(ent_packet))

    def help1(self):
        ent_packet = f"120000013108{self.EncryptedPlayerid}101220022aa40208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}228b015b625d5b666661303030d9905d20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4d8aed985d8b3d8a920d981d98a20d8a7d984d981d8b1d98ad982203a20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a42f35e385a420e385a4e385a4e385a4e385a428e3eeb4b5064a280a21e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e28c9a20c9013802520261726a520a4c68747470733a2f2f7062732e7477696d672e636f6d2f70726f66696c655f696d616765732f1815038486585442304/554b3170536d77485f6e6f726d616c2e6a7067100118017200"
        self.sock1200.send(bytes.fromhex(ent_packet))

    def help2(self):
        ent_packet = f"12000000b908{self.EncryptedPlayerid}101220022aac0108{self.EncryptedPlayerid}10{self.EncryptedPlayerid}227b5b625d5b666661303030d9905d20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a43620d981d98a20d8a7d984d981d8b1d98ad982203a20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a42f36e385a420e385a4e385a4e385a4e385a428fcbc8eb9064a0f0a0a506f756c6574325a314a20c901520261726a04100118017200"
        self.sock1200.send(bytes.fromhex(ent_packet))

    def help3(self):
        ent_packet = f"120000012108{self.EncryptedPlayerid}101220022a940208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}227c5b625d5b666661303030d9905d20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4d8b5d8afd98ad98220d988d987d985d98a203a20e385a4e385a4e385a4e385a4e385a42f69642031323320343536e385a420e385a4e385a4e385a4e385a428eeeeb4b5064a280a21e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e28c9a20c9013802520261726a520a4c68747470733a2f2f7062732e7477696d672e636f6d2f70726f66696c655f696d616765732f1815038486585442304/554b3170536d77485f6e6f726d616c2e6a7067100118017200"
        self.sock1200.send(bytes.fromhex(ent_packet))

    def help4(self):
        ent_packet = f"120000012b08{self.EncryptedPlayerid}101220022a9e0208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2285015b625d5b666661303030d9905d20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4d8b3d8a8d8a7d98520d8b7d984d8a820d8a7d984d8a7d986d8b6d985d8a7d985203a20e385a4e385a4e385a4e385a4e385a42f696e7620e385a420e385a4e385a4e385a4e385a428f9eeb4b5064a280a21e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e28c9a20c9013802520261726a520a4c68747470733a2f2f7062732e7477696d672e636f6d2f70726f66696c655f696d616765732f1815038486585442304/554b3170536d77485f6e6f726d616l2e6a7067100118017200"
        self.sock1200.send(bytes.fromhex(ent_packet))

    def help5(self):
        ent_packet = f"120000012908{self.EncryptedPlayerid}101220022a9c0208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2283015b625d5b666661303030d9905d20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4d8b1d982d8b5d8a7d8aa3a20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a42f6131202d2d2d2d3e202f613133e385a420e385a4e385a4e385a4e385a4288eefb4b5064a280a21e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e29a91e28c9a20c9013802520261726a520a4c68747470733a2f2f7062732e7477696d672e636f6d2f70726f66696c655f696d616765732f1815038486585442304/554b3170536d77485f6e6f726d616c2e6a7067100118017200"
        self.sock1200.send(bytes.fromhex(ent_packet))

    def help6(self):
        ent_packet = f"120000012e08{self.EncryptedPlayerid}101220022aa10208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}2288015b625d5b666661303030d9905d20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a420d8a7d984d8a8d8afd8a720d8a7d8acd8a8d8a7d8b1d98a20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a42f737461727420e385a428a7efb4b5064a280a21e29a91e29a91e29a91e29a91e29a91e29a91e29a9129a91e29a91e29a91e28c9a20c9013802520261726a520a4c68747470733a2f2f7062732e7477696d672e636f6d2f70726f66696c655f696d616765732f1815038486585442304/554b3170536d77485f6e6f726d616c2e6a7067100118017200"
        self.sock1200.send(bytes.fromhex(ent_packet))

    def help7(self):
        ent_packet = f"120000011208{self.EncryptedPlayerid}101220022a850208{self.EncryptedPlayerid}10{self.EncryptedPlayerid}225c5b625d5b4646613030305d20e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4e385a4d8acd984d8a820d985d8b7d988d8b120d8a8d988d8aa203a202f686578e385a4289090bbbc064a380a21e28094cd9ecd9fcd9ee29885efbca8efbcafefbcb3efbcb3efbca1efbcadefbca510f9db8dae0318c5d8d0ad0320cf012885fff5b103520261726a530a4d68747470733a2f2f67726170682e66616365626f6f6b2e636f6d2f76392e302f323335383432343031343430383133372f706963747572653f77696474683d313630266865696768743d313630100118017200"
        self.sock1200.send(bytes.fromhex(ent_packet))

    def exchange_loop(self, client, remote):
        global inviteD
        global back
        global Ghost
        global enc_client_id

        while True:
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                dataC = client.recv(4096)

                if "39698" in str(remote):
                    self.op = remote
                if "39800" in str(remote):
                    self.xz = remote

                if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 820 and inviteD == True:
                    for i in range(2):
                        for _ in range(5):
                            remote.send(dataC)
                            time.sleep(0.04)
                        time.sleep(0.2)

                if '0515' in dataC.hex()[0:4] and len(dataC.hex()) >= 141:
                    self.data_join = dataC

                if remote.send(dataC) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if '1200' in data.hex()[0:4] and b'GroupID' not in data:
                    start_marker = "08"
                    end_marker = "10"
                    start_index = data.hex().find(start_marker) + len(start_marker)
                    end_index = data.hex().find(end_marker, start_index)
                    if start_index != -1 and end_index != -1:
                        enc_client_id = data.hex()[start_index:end_index]
                        self.EncryptedPlayerid = enc_client_id
                    self.squad_gen = self.Encrypt_ID(8763797454)
                    self.squad_gen5 = self.Encrypt_ID(2064377560)
                    self.squad = self.Encrypt_ID(8679231987)
                    current_time = time.time()
                    if current_time - self.last_check_time >= 86400:
                        external_data = self.fetch_data_from_url()
                        if external_data and enc_client_id in external_data:
                            print("Encrypted Player id matches data.txt content.")
                            Ghost = False
                        else:
                            print("id does not match or error fetching data.txt.")
                            Ghost = True
                        self.last_check_time = current_time
                if "0500" in data.hex()[:4]:
                    self.sock0500 = client
                if "1200" in data.hex()[:4]:
                    self.sock1200 = client
                if '1200' in data.hex()[0:4] and b'/inv' in data:
                    inviteD = True
                if '1200' in data.hex()[0:4] and b'/-inv' in data:
                    inviteD = False

                if '1200' in data.hex()[0:4] and b'/id' in data:
                    i = re.split('/id', str(data))[1]
                    if '' in i:
                        i = i.replace('', '106')
                    id = str(i).split('(\\x')[0]
                    id = self.Encrypt_ID(id)
                    self.fake_friend(self.sock0500, id)

                # 5 in Squad
                if '1200' in data.hex()[0:4] and b'/5' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.gen_squad5).start()

                # bot3
                if '1200' in data.hex()[0:4] and b'/6' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.gen_squad6).start()

                if '1200' in data.hex()[0:4] and b'/hex' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.gen_squad8).start()
                if '1200' in data.hex()[0:4] and b'/start' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.invisible1).start()

                if '1200' in data.hex()[0:4] and b'help' in data:
                    try:
                        threading.Thread(target=self.help).start()
                        threading.Thread(target=self.help1).start()
                        threading.Thread(target=self.help2).start()
                        threading.Thread(target=self.help3).start()
                        threading.Thread(target=self.help4).start()
                        threading.Thread(target=self.help5).start()
                        threading.Thread(target=self.help6).start()
                        threading.Thread(target=self.help7).start()
                    except Exception as e:
                        pass

                # Dance
                if '1200' in data.hex()[0:4] and b'/a1' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance).start()

                if '1200' in data.hex()[0:4] and b'/a2' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance2).start()

                if '1200' in data.hex()[0:4] and b'/a3' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance3).start()

                if '1200' in data.hex()[0:4] and b'/a4' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance4).start()

                if '1200' in data.hex()[0:4] and b'/a5' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance5).start()

                if '1200' in data.hex()[0:4] and b'/a6' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance6).start()

                if '1200' in data.hex()[0:4] and b'/a7' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance7).start()

                if '1200' in data.hex()[0:4] and b'/a8' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance8).start()

                if '1200' in data.hex()[0:4] and b'/a9' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance9).start()

                if '1200' in data.hex()[0:4] and b'/a10' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance10).start()

                if '1200' in data.hex()[0:4] and b'/a11' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance11).start()

                if '1200' in data.hex()[0:4] and b'/a12' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance12).start()

                if '1200' in data.hex()[0:4] and b'/a13' in data and 700 > len(data.hex()):
                    threading.Thread(target=self.Dance13).start()

                if "1200" in data.hex()[:4] and Ghost == True:
                    self.send(bytes.fromhex(gen_msgv2(data.hex(), "[E0FF00]hhhhhhhhhhCHAT SPAMMER: [00FFbb0hehehehehehehhehehehh0]ON")))

                if client.send(data) <= 0:
                    break

    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(4, 'big'),
            int(0).to_bytes(4, 'big')
        ])

    def verify_credentials(self, connection):
        version = connection.recv(1)[0]
        username_len = connection.recv(1)[0]
        username = connection.recv(username_len).decode('utf-8')
        password_len = connection.recv(1)[0]
        password = connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            response = bytes([version, 0])
            connection.sendall(response)
            return True
        else:
            response = bytes([version, 0])
            connection.sendall(response)
            return True

    def get_available_methods(self, nmethods, connection):
        methods = []
        for _ in range(nmethods):
            methods.append(connection.recv(1)[0])
        return methods

    def run(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((ip, port))
        s.listen()
        print(f"* Socks5 proxy server is running on {ip}:{port}")

        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=self.handle_client, args=(conn,))
            t.start()

    def ghost(self, data_join):
        global back
        while back:
            try:
                self.op.send(data_join)
                time.sleep(9999.0)
            except Exception as e:
                pass

    def fetch_data_from_url(self):
        data_url = "https://xtz-time-apk.vercel.app/Uids"
        try:
            response = requests.get(data_url, verify=False)
            if response.status_code == 200:
                return response.text
            else:
                print("Failed to fetch external data. Status code:", response.status_code)
                return None
        except requests.RequestException as e:
            print("Failed to connect to external data source:", e)
            return None

def gen_msgv2(packet, replay):
    replay = replay.encode('utf-8')
    replay = replay.hex()

    hedar = packet[0:8]
    packetLength = packet[8:10]
    paketBody = packet[10:32]
    pyloadbodyLength = packet[32:34]
    pyloadbody2 = packet[34:60]
    pyloadlength = packet[60:62]
    pyloadtext = re.findall(r'{}(.*?)28'.format(pyloadlength), packet[50:])[0]
    pyloadTile = packet[len(pyloadtext) + 62:]

    # حساب الطول الجديد للنص
    new_text_value = (int(f'0x{pyloadlength}', 16) 
                     - int(len(pyloadtext) // 2) 
                     + int(len(replay) // 2))
    
    NewTextLength = hex(new_text_value)[2:]
    
    # إضافة صفر بادئ إذا كان طول السلسلة 1
    if len(NewTextLength) == 1:
        NewTextLength = "0" + NewTextLength

    # حساب الطول الجديد للباكيت
    new_packet_value = (int(f'0x{packetLength}', 16) 
                        - int(len(pyloadtext) // 2) 
                        + int(len(replay) // 2))
    
    NewpaketLength = hex(new_packet_value)[2:]
    if len(NewpaketLength) == 1:
        NewpaketLength = "0" + NewpaketLength

    # حساب الطول الجديد للـ payload body
    new_payload_value = (int(f'0x{pyloadbodyLength}', 16) 
                         - int(len(pyloadtext) // 2) 
                         + int(len(replay) // 2))
    
    NewPyloadLength = hex(new_payload_value)[2:]
    if len(NewPyloadLength) == 1:
        NewPyloadLength = "0" + NewPyloadLength

    finallyPacket = (hedar + NewpaketLength + paketBody + 
                    NewPyloadLength + pyloadbody2 + 
                    NewTextLength + replay + pyloadTile)

    return finallyPacket

def start_bot():
    proxy = Proxy()
    proxy.run("127.0.0.1", 6000)

if __name__ == "__main__":
    start_bot()