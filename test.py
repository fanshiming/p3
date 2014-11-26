# -*- coding: utf-8 -*-

import p1

def keybreakup():
    mkey = b'\x11\x22\x33\x44\x55\x66\x77\x88'
    subkey = p1.key_breakup_to16keys(key=mkey)
    for k in subkey:
        print(subkey[k])

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


if __name__=='__main__':
    
    #temp()
    keybreakup()