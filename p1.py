# -*- coding: utf-8 -*-

'''
python3.4
'''


def key_breakup_to16keys(key=None):
    '''处理秘钥。将64位key转换为16个子秘钥

    Keyword arguments:
    key     --  64位秘钥, bytes

    Returns:
    subkey --  {key_idx:key_data,...}
    '''

    if key is None:
        raise BaseException('key is None')


    if len(key) != 8:
        raise BaseException('key_len must be 64 bits')

    #python没有位处理，这里变换为key[64],其中1=true， 0=false
    key = int.from_bytes(key, 'big')
    key64=[]
    idx = 0
    while idx < 64:
        t = (key << idx) & 0x80000000
        idx = idx + 1
        if t != 0:
            key64.append(True)
        else:
            key64.append(False)

    #校验   秘钥需要具备奇数个1
    #idx = 0
    #for t in key64:
    #    if t:
    #        idx = idx + 1
    #if idx%2 == 0:
    #    raise BaseException('需要奇数个1')


    #对key[64]做变换，得keyT[56]
    keyT56 = []
    idx = (56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18, 10,  2,59, 51, 43, 35,62, 54, 46, 38, 30, 22, 14,  6,61, 53, 45, 37, 29, 21, 13,  5,60, 52, 44, 36, 28, 20, 12,  4,27, 19, 11,  3 )
    for i in idx:
        keyT56.append(key64[i])

    #依据keyT56获得C D
    c28 = keyT56[0:28]
    d28 = keyT56[28:]


    #计算16个子密钥subkey
    idx = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15)
    ls = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
    subkey={}
    for i in idx:
        subkey_idx = ( 13,16,10,23, 0,  4, 2,27,14, 5,20, 9, 22,18,11, 3,25,  7,15, 6,26,19,12, 1, 40,51,30,36,46, 54,29,39,50,44,32,47, 43,48,38,55,33, 52,45,41,49,35,28,31)
        sub_c28=[]
        n = ls[i]
        sub_c28 = sub_c28 + c28[n:]
        sub_c28 = sub_c28 + c28[0:n]  

        sub_d28=[]
        n = ls[i]
        sub_d28 = sub_d28 + d28[n:]
        sub_d28 = sub_d28 + d28[0:n] 

        cd56 = sub_c28 + sub_d28

        subkey_temp = []
        for si in subkey_idx:
            subkey_temp.append(cd56[si])
        subkey[i] = subkey_temp

    return subkey


