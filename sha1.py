# coding:utf-8
# SHA-1を自分で実装したい
# 512bitが1ブロック (32byte)
import sys
import struct
import hashlib
from Crypto.Util.number import bytes_to_long as b2l
from m1z0r3.crypro import split_n
import string


# ===== Constant Value =====
block_len = 512
K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

def f(t,B,C,D):
    if 0 <= t and t < 20:
        return (B & C) | (bit_inv(B) & D)
    elif (20 <= t and t < 40) or (60 <= t and t < 80):
        return B ^ C ^ D
    elif 40 <= t and t < 60:
        return (B & C) | (B & D) | (C & D)
    else:
        print "t is invalid."
        sys.exit()
    
# 32bitワードごとの反転
# なので, ^0xffffffff(32bit)で反転．
def bit_inv(word):
    return word ^ 0xffffffff

# nビット循環左シフト
def sha1_circular_shift(bits,word):
    return ((word << bits) & 0xffffffff) + (word >> 32-bits)

def cmb_result(L):
    ret = ""
    for i in xrange(len(L)):
        ret += hex(L[i])[2:-1].zfill(8)
    return ret

# paddingの時の長さを取る関数
# 4ビットずつ区切るので4の倍数になるはず
def bit_len(word):
    b_len = len(bin(word)[2:])
    while b_len%4 != 0:
        b_len += 1
    return b_len
    
# 4の倍数ビットになるようゼロフィルしたものを返す
def zfill_bin(message):
    message = bin(message)[2:]
    while len(message)%4 != 0:
        message = "0" + message
    return message

def sha1_padding(message):
    message_len = bit_len(message)
    l = message_len
    print "==== メッセージの最下位に1を付加したもの"
    print zfill_bin(message)+"1"
    message = (message << 1) + 1
    message_len += 1 # 上で下位に1ビット付加しているので長さも1増やす

    # 0を，ここまでのメッセージ長を512で割った余りが64になるまでくっつけたい
    # そうなるようパディング長を計算する
    padding_len = block_len - 64 - message_len
    padding_len = 0 
    while block_len - message_len % block_len != 64:
        message_len += 1
        padding_len += 1

    print "==== パディングの長さ ===="
    print padding_len
    message = message << padding_len
    print "==== パディング後のメッセージ ===="
    print hex(message)
    print "==== パディング後のメッセージの長さ ===="
    print bit_len(message)
 
    message = (message << 64) + l
    print "==== 最後のメッセージ長を付加したもの ===="
    print hex(message)
    print "==== パディング処理完了後のメッセージの長さ ===="
    print bit_len(message)
    
    return message


def main():
    # IPAの4章のメッセージパディング
    # ==== Input ====
    #message = 0b01010000
    #message = 0b0110000101100010011000110110010001100101
    #test_message = open("a.exe","r").read()
    test_message = "ABCDE"*100
    message = b2l(test_message)
    message_len = bit_len(message) 

    print "==== メッセージを4の倍数になるようにしてbinに直すと ===="
    print zfill_bin(message)
    print "===== メッセージの長さ ====="
    print message_len
    l = message_len

    message = sha1_padding(message)

    for block in split_n(zfill_bin(message),512):
        message = int(block,2)
        # メッセージダイジェストの計算
        W = []
        # まずW[0] ~ W[15]までの16個を入れる
        for i in xrange(16):
            W.append(message >> 32*(15-i) & 0xffffffff)

        # W[16]からは以下の式通りに入れる
        # S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16))
        # なお，S^n はnビット循環左シフトを示す
        for t in xrange(16,80):
            W.append(sha1_circular_shift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]))
        print map(hex,W)

        A = H[0]
        B = H[1]
        C = H[2]
        D = H[3]
        E = H[4]


        # 0 ~ 79までのtに対して以下の計算を行う
        # TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
        #  E = D; D = C; C = S^30(B); B = A; A = TEMP;
        for t in xrange(80):
            TEMP = (sha1_circular_shift(5,A) + f(t,B,C,D) + E + W[t] + K[t/20]) & 0xffffffff # "& 0xf..."は "% 2**32"
            E = D
            D = C
            C = sha1_circular_shift(30,B)
            B = A
            A = TEMP
        H[0] = (H[0] + A) & 0xffffffff
        H[1] = (H[1] + B) & 0xffffffff
        H[2] = (H[2] + C) & 0xffffffff
        H[3] = (H[3] + D) & 0xffffffff
        H[4] = (H[4] + E) & 0xffffffff
    
    print cmb_result(H)
    print hashlib.sha1(test_message).hexdigest()

if __name__ == "__main__":
    main()
