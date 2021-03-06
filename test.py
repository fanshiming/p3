# -*- coding: utf-8 -*-

import p1

mkey = b'\x11\x22\x33\x44\x55\x66\x77\x88'
plain_test = b'\xaa\xbb\xcc\xdd\x11\x22\x33\x44'

mkey = b'\x73\x65\x63\x75\x72\x69\x74\x79'
plain_test = b'\x63\x6f\x6d\x70\x75\x74\x65\x72'

#3des的秘钥
tmkey = mkey + mkey


def keybreakup():
    subkey = p1.key_breakup_to16keys(key=mkey)
    for k in subkey:
        print_boollist(k)

def plain_text_lr0_test():
    plain_text = b'\x11\x22\x33\x44\x55\x66\x77\x88'
    l0, r0 = p1.plain_text_lr0(plain_text)
    print(l0)
    print(r0)

    er48 = p1.r32_to_er48(r0)
    print(er48)

def temp():
    b = b'\x11\x22\x33\x44\x55\x66\x77\x88'
    print(b)
    bb = b <<1
    print(bb)
    c = int.from_bytes(b, 'big')
    print(c)
    c = c << 1
    print(c)
    a = 1
    a = a << 1
    print(a)

def print_boollist(blist=None):
    if blist is None:
        return
    v = 0
    for b in blist:
        v = v << 1
        if b:
            v = v + 1
    nbytes, rem = divmod(v.bit_length(), 8)
    if rem:
        nbytes += 1
    bs = v.to_bytes(nbytes, 'big')
    print_bytes(bs)

def print_bytes(bs=None):
    if bs is None:
        return

    s = ''
    for b in bs:
        s = s + '%02x'%b + ''
    print(s)

def l0r0():
    mkey = b'\x73\x65\x63\x75\x72\x69\x74\x79'
    plain_test = b'\x63\x6f\x6d\x70\x75\x74\x65\x72'
    l0, r0 = p1.plain_text_lr0(plain_test)

    v = 0 
    for b in l0:
        v = v << 1
        if b:
            v = v + 1
    print_bytes(v.to_bytes(4,'big'))

    v = 0 
    for b in r0:
        v = v << 1
        if b:
            v = v + 1
    print_bytes(v.to_bytes(4,'big'))




def des_encrypt():


    print('mkey')
    print_bytes(mkey)
    print_bytes(plain_test)

    v = p1.des_encrypt(key = mkey, plain_bytes = plain_test)
    print_bytes(v)

    v2 = p1.des_decrypt(key = mkey, bs = v)
    print_bytes(v2)

def tdes():
    print('tmkey')
    print_bytes(tmkey)
    print_bytes(plain_test)

    v = p1.tdes_encrypt(key = tmkey, plain_bytes = plain_test)
    print_bytes(v)

    v2 = p1.tdes_decrypt(key = tmkey, bs = v)
    print_bytes(v2)

if __name__=='__main__':
    
    #keybreakup()
    #temp()
    #des_encrypt()
    #l0r0()
    tdes()
