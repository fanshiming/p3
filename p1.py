# -*- coding: utf-8 -*-

'''
python3.4

没有找到直接的位处理类型，这里将使用 true, false 的序列代替位串。
'''


def fortest_print_bool(bs = None):
    v = 0
    for b in bs:
        v =  v << 1
        if b:
            v = v + 1

    x = v.to_bytes(8, 'big')
    s = ''
    for b in x:
        s = s + '%02x'%b 
    print(s)

def key_breakup_to16keys(key=None):
    '''处理秘钥。将64位key转换为16个子秘钥

    Keyword arguments:
    key     --  64位秘钥, bytes

    Returns:
    subkey --  共计16个子密钥 (true,false,true,....)
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
        t = (key << idx) & 0x8000000000000000
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
        
        sub_c28=[]
        n = ls[i]
        sub_c28 = sub_c28 + c28[n:]
        sub_c28 = sub_c28 + c28[0:n]  

        sub_d28=[]
        n = ls[i]
        sub_d28 = sub_d28 + d28[n:]
        sub_d28 = sub_d28 + d28[0:n] 

        cd56 = sub_c28 + sub_d28

        subkey_idx = ( 13,16,10,23, 0,  4, 2,27,14, 5,20, 9, 22,18,11, 3,25,  7,15, 6,26,19,12, 1, 40,51,30,36,46, 54,29,39,50,44,32,47, 43,48,38,55,33, 52,45,41,49,35,28,31)
        subkey_temp = []
        for si in subkey_idx:
            subkey_temp.append(cd56[si])
        yield subkey_temp



def plain_text_lr0(plain_text=None):
    '''将64位待加密数据，转换为L0，R0

    Keyword arguments:
    plain_text  --  待加密的64位数据

    Returns:
    转换后的L0，R0   --  (L0,R0), L0 R0长度都是32长度,(true,false,,,)形式的序列
    '''

    if plain_text is None:
        raise BaseException('plain_text is None')
    if len(plain_text) != 8:
        raise BaseException('plain_text must be 64 bits')

    #python没有位处理，这里变换为bit sequence[64],其中1=true， 0=false
    plain_text = int.from_bytes(plain_text, 'big')
    bs64=[]
    idx = 0
    while idx < 64:
        t = (plain_text << idx) & 0x8000000000000000
        idx = idx + 1
        if t != 0:
            bs64.append(True)
        else:
            bs64.append(False)

    #L0在明文中的下标
    idx = (58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 )
    LR0 = []
    for i in idx:
        LR0.append(bs64[i-1])

    L0 = LR0[0:32]
    R0 = LR0[32:]

    return (L0,R0)


def r32_to_er48(Rx=None):
    '''将32位R序列转换为48位R序列

    Keyword arguments:
    Rx --   待转换的32位R序列，是一个[true,false,...]

    Returns:
    Rnew    --  转换后的48位R序列  [true, false,...]
    '''

    if Rx is None:
        raise BaseException('Rx is None')

    if len(Rx) != 32:
        raise BaseException('Len of Rx must 32')

    #扩展后的序列，在R32的下标索引值
    idx = ( 31,  0,  1,  2,  3,  4, 3,  4,  5,  6,  7,  8, 7,  8,  9, 10, 11, 12,11, 12, 13, 14, 15, 16,15, 16, 17, 18, 19, 20,19, 20, 21, 22, 23, 24,23, 24, 25, 26, 27, 28,27, 28, 29, 30, 31,  0)

    exR48 =[]
    for i in idx:
        exR48.append(Rx[i])

    return exR48

def _b48(Bx = None):
    '''将48位B序列，生成对应的密盒索引，用于密盒变换
    '''
    if Bx is None:
        raise BaseException('Bx is None')
    if len(Bx) != 48:
        raise BaseException('len of bx must 48')

    i = 0       #从第0组开始
    gs = 8      ##一共8组
    count = 6   #每6位一组
    while i < gs:
        offset = i * count
        rowNum = 0
        if Bx[offset]:
            rowNum = 2
        if Bx[offset+5]:
            rowNum = rowNum + 1
        colNum = 0
        temp_i = offset + 1
        while temp_i < offset + 5:
            colNum = colNum << 1
            if Bx[temp_i]:
                colNum = colNum + 1
            temp_i = temp_i + 1

        idx_in_s = rowNum * 16 + colNum
        idx_in_s = i * 64 + idx_in_s
        yield idx_in_s
        i = i + 1



def b48_to_temp1(Bx = None):
    '''将48位B序列，经过8个密盒变换后，形成一个临时32位序列

    Keyword arguments:
    Bx  --  进入密盒变换前的48位序列

    Returns:
    temp1    --  8密盒变换后形成的一个新32位序列 [true, false,...]
    '''

    if Bx is None:
        raise BaseException('Bx is None')
    if len(Bx) != 48:
        raise BaseException('len of bx must 48')

    #8个密盒 s1-s8
    s1 = (14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13)

    s2 = (15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9)

    s3 = (10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12)

    s4 = (7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14)

    s5 = (2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3)

    s6 = (12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13)

    s7 = (4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12)

    s8 = (13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11)

    s = s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8 

    sv = []
    for b in _b48(Bx):
        v = s[b]
        #将V处理为4位序列        
        if (v & 0x08) != 0:
            sv.append(True)
        else:
            sv.append(False)
        if (v & 0x04) != 0:
            sv.append(True)
        else:
            sv.append(False)
        if (v & 0x02) != 0:
            sv.append(True)
        else:
            sv.append(False)
        if (v & 0x01) != 0:
            sv.append(True)
        else:
            sv.append(False)

    idx = (15,  6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25,  4, 17, 30,  9, 1,  7, 23, 13, 31, 26,  2,  8,18, 12, 29,  5, 21, 10,  3, 24)
    sv_new = []
    for i in idx:
        sv_new.append(sv[i])
    return sv_new

def des_encrypt(key=None, plain_bytes=None):
    '''DES加密

    Keyword arguments:
    key     --  64位秘钥  bytes 
    plain_bytes     --  64位明文

    Returns:
    bytes   --  加密后的64位密文
    '''

    if key is None or plain_bytes is None:
        raise BaseException('param is None')
    if len(key) != 8 or len(plain_bytes) != 8:
        raise BaseException('len of param must be 64bits')

    #依据明文计算出 L0 R0
    L0, R0 = plain_text_lr0(plain_bytes)

    li = L0 
    ri = R0 
    #使用这16个子密钥
    for subKey in key_breakup_to16keys(key):
        #将R扩充至48位
        er48 = r32_to_er48(ri)

        #与子密钥做异或运算，得到B序列
        bi = []
        temp_i = 0
        while temp_i < 48:
            bi.append(er48[temp_i] ^ subKey[temp_i])
            temp_i = temp_i + 1

        
        #计算新32位序列
        temp1 = b48_to_temp1(bi)

        #计算出下一个ri 和 li
        ri_next = []
        temp_i = 0
        while temp_i < 32:
            ri_next.append(temp1[temp_i] ^ li[temp_i])
            temp_i =  temp_i + 1

        li_next = ri

        #更新下一轮使用到的 ri  li 
        ri = ri_next
        li = li_next

    #组合R16 L16
    rl32 = ri + li 
    idx = (40, 8, 48, 16, 56, 24, 64, 32,39, 7, 47, 15, 55, 23, 63, 31,38, 6, 46, 14, 54, 22, 62, 30,37, 5, 45, 13, 53, 21, 61, 29,36, 4, 44, 12, 52, 20, 60, 28,35, 3, 43, 11, 51, 19, 59, 27,34, 2, 42, 10, 50, 18, 58, 26,33, 1, 41, 9 ,49 ,17 ,57 ,25 )      #这里的下标值都需要-1才是真正的下标索引。在网上没有找到更合适的逆函数矩阵

    cip =[]
    for i in idx:
        cip.append(rl32[i-1])

    #CIP依然是我们内部使用(true, false,...)序列表示的，将CIP转换为bytes
    v = 0 
    for b in cip:
        v = v << 1
        if b:
            v = v + 1
    return v.to_bytes(8,'big')


def des_decrypt(key=None, bs=None):
    '''DES解密

    Keyword arguments:
    key     --  64位秘钥  bytes 
    bs     --  64位密文

    Returns:
    bytes   --  64位
    '''

    if key is None or bs is None:
        raise BaseException('param is None')
    if len(key) != 8 or len(bs) != 8:
        raise BaseException('len of param must be 64bits')

    #依据明文计算出 L0 R0
    L0, R0 = plain_text_lr0(bs)

    li = L0 
    ri = R0 

    subKeys = []
    for sk in key_breakup_to16keys(key):
        subKeys.insert(0,sk)
    #使用这16个子密钥
    for subKey in subKeys:
        #将R扩充至48位
        er48 = r32_to_er48(ri)

        #与子密钥做异或运算，得到B序列
        bi = []
        temp_i = 0
        while temp_i < 48:
            bi.append(er48[temp_i] ^ subKey[temp_i])
            temp_i = temp_i + 1

        
        #计算新32位序列
        temp1 = b48_to_temp1(bi)

        #计算出下一个ri 和 li
        ri_next = []
        temp_i = 0
        while temp_i < 32:
            ri_next.append(temp1[temp_i] ^ li[temp_i])
            temp_i =  temp_i + 1

        li_next = ri

        #更新下一轮使用到的 ri  li 
        ri = ri_next
        li = li_next

    #组合R16 L16
    rl32 = ri + li 
    idx = (40, 8, 48, 16, 56, 24, 64, 32,39, 7, 47, 15, 55, 23, 63, 31,38, 6, 46, 14, 54, 22, 62, 30,37, 5, 45, 13, 53, 21, 61, 29,36, 4, 44, 12, 52, 20, 60, 28,35, 3, 43, 11, 51, 19, 59, 27,34, 2, 42, 10, 50, 18, 58, 26,33, 1, 41, 9 ,49 ,17 ,57 ,25 )      #这里的下标值都需要-1才是真正的下标索引。在网上没有找到更合适的逆函数矩阵

    cip =[]
    for i in idx:
        cip.append(rl32[i-1])

    #CIP依然是我们内部使用(true, false,...)序列表示的，将CIP转换为bytes
    v = 0 
    for b in cip:
        v = v << 1
        if b:
            v = v + 1
    return v.to_bytes(8,'big')

