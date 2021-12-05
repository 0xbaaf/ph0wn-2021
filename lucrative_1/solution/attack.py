from time import time
from hashlib import sha256
from binascii import unhexlify

logs = [{'username': 'Wendel', 'timestamp': 1638553108, 'token': '11c26663ebab3e896e68df6dc949043a1c4345843b76d4c6ee20ba08', 'proof': 'd3c1d2db945eec8e5469151a3dc3e0cf65c92dc77796cdb6f0e245c0591e5913'},
{'username': 'Wendel', 'timestamp': 1638553113, 'token': '11c2666e629f58d35d6133d96b704002b3e88854cf5fb66628afc748', 'proof': 'd3c1d2db945eec8e5469151a3dc3e0cf65c92dc77796cdb6f0e245c0591e5913'},
{'username': 'Freyr', 'timestamp': 1638553117, 'token': '11c2666a81144203c10aa6ccbeac768bfa2f61df376ab3cc688ab0a6', 'proof': 'fe5a6bc3d817913e39f9be4b7d7bafa9747e80a45d1f4ef2ef1db47ff789ef04'},
{'username': 'Vlastimir', 'timestamp': 1638553120, 'token': '11c266571bd1c8a516dc8da0208245795c819ad9bc6bde4e0abc23e2', 'proof': '6edb172df503b98194a74813d849b84d2274d6b7b521da1d19ca00818d38f06d'},
{'username': 'Wendel', 'timestamp': 1638553124, 'token': '11c266535bea78698d7ecb2df3cd18ba55bbfa84e16f06c6c1ea7e08', 'proof': 'd3c1d2db945eec8e5469151a3dc3e0cf65c92dc77796cdb6f0e245c0591e5913'},
{'username': 'Wendel', 'timestamp': 1638553128, 'token': '11c2665fcfe5a621da444edd416c145ae7ad9344ea955b46f85cef08', 'proof': 'd3c1d2db945eec8e5469151a3dc3e0cf65c92dc77796cdb6f0e245c0591e5913'},
{'username': 'Vlastimir', 'timestamp': 1638553131, 'token': '11c2665c0806bcf8db4ff037e50611145bcaeb0220c4eecbe2d19f0d', 'proof': '6edb172df503b98194a74813d849b84d2274d6b7b521da1d19ca00818d38f06d'},
{'username': 'Vlastimir', 'timestamp': 1638553136, 'token': '11c2664729efba55ef365050f55658699888fec9b2ca697e915879f2', 'proof': '6edb172df503b98194a74813d849b84d2274d6b7b521da1d19ca00818d38f06d'},
{'username': 'Wendel', 'timestamp': 1638553141, 'token': '11c266426f289cdbfec7a4a900292e62f177919489e7c5e6b5d0de48', 'proof': 'd3c1d2db945eec8e5469151a3dc3e0cf65c92dc77796cdb6f0e245c0591e5913'},
{'username': 'Wendel', 'timestamp': 1638553146, 'token': '11c2664de61c36e52d3cfb05a2d06a4a681dc4649dcca706fe5feb88', 'proof': 'd3c1d2db945eec8e5469151a3dc3e0cf65c92dc77796cdb6f0e245c0591e5913'},
{'username': 'Wendel', 'timestamp': 1638553150, 'token': '11c266499a0c64bd7a027e357073656aba0ffc24a74afb86b6d25c88', 'proof': 'd3c1d2db945eec8e5469151a3dc3e0cf65c92dc77796cdb6f0e245c0591e5913'},
{'username': 'Vlastimir', 'timestamp': 1638553155, 'token': '11c26634cf20d610e7af2b2f52f1c58c01d0113a5a5abe63defe2025', 'proof': '6edb172df503b98194a74813d849b84d2274d6b7b521da1d19ca00818d38f06d'}]

class Cipher:
    def __init__(self,a,b):
        self.a = a
        self.b = b
        self.m = 2 ** 32

    def next_state(self):
        self.state = (self.a * self.state + self.b) % self.m

    def set_seed(self,seed):
        self.state = seed

    def output(self):
        return self.state.to_bytes(4,byteorder="big")

def xor(a,b):
    return bytes(x^y for x,y in zip(a,b))

def encrypt(pt):
    seed = int(time())
    cipher.set_seed(seed)
    pt += (4 - (len(pt) % 4)) * b"\x00"
    ct = b""
    for i in range(0,len(pt),4):
        ct += xor(cipher.output(),pt[i:i+4])
        cipher.next_state()
    return ct, seed

def decrypt(ct,t):
    seed = t
    cipher.set_seed(seed)
    assert(len(ct)%4 == 0)
    pt = b""
    for i in range(0,len(ct),4):
        pt += xor(cipher.output(),ct[i:i+4])
        cipher.next_state()

    #unpad
    while pt[-1] == 0:
        pt = pt[:-1]
    return pt

def origin_client():
    A = int(input("A:")) % 2 ** 32
    B = int(input("B:")) % 2 ** 32
    assert 2 <= A < 2 ** 32
    assert 2 <= B < 2 ** 32

    cipher = Cipher(A,B)

    username = input("username: ")
    password = b"ph0wn:" + input("password: ").encode()
    enc, timestamp = encrypt(password)

    print("auth_token:",{"username":username,"timestamp":timestamp,"token":enc.hex(),"proof": sha256(A.to_bytes(4,byteorder="big") + B.to_bytes(4,byteorder="big") + password).hexdigest()})




username = logs[0]['username']
assert(username==logs[1]['username'])

proof = logs[0]['proof']
assert(proof==logs[1]['proof'])

c1 = unhexlify(logs[0]['token'])
c2 = unhexlify(logs[1]['token'])

t1 = logs[0]['timestamp']
t2 = logs[1]['timestamp']

m = 2**32

# let's rewrite things
# password is the name and starts with "ph0wn:"
# let's focus on the second block (4 bytes) where the key stream gets involved
# c1 and c2 are the second block of the token (encrypted password)
#
# c1 = p xor (a*t1 + b)
# c2 = p xor (a*t2 + b)
# 
# c1 xor p = a*t1 + b
# c2 xor p = a*t2 + b
#
# (c1 xor p) - b = a*t1
# (c2 xor p) - b = a*t2
#
# a*(t2-t1) = (c2 xor p) - (c1 xor p)
# a = [ (c2 xor p) - (c1 xor p) ]* inv(t2-t1)
#
# So we have c1,c2,t1, t2 and part of p (16 bits "n:" from the second block)
# The only unknown are 16 bits of p
# Let's brute fore the remaining 16 bits of p.

for unknown_p in range(2**16):
    p = b'n:'+unknown_p.to_bytes(2,'big')

    x1 = int.from_bytes(xor(c1[4:8],p),'big')
    x2 = int.from_bytes(xor(c2[4:8],p),'big')
    s = (x2 - x1)
    inv_dt = pow(t2-t1,-1,m)

    a = (s*inv_dt) % m
    b = (x1 - a*t1) % m

    if a < 2 or b < 2:
        continue

    cipher = Cipher(a,b)
    password = decrypt(c1,t1)

    ss = sha256(a.to_bytes(4,byteorder="big") + b.to_bytes(4,byteorder="big") + password).hexdigest()
    if ss == proof:
        print("FOUND:", password,a,b)
        break
