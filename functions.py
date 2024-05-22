
from DES import *;

def get_R16_L16(cipher):
    bin_cipher = bin(int(cipher, 16))[2:].zfill(64)

    reverse = initial_perm(bin_cipher)
    L16 = reverse[32:64]
    R16 = reverse[:32]
    return R16, L16


def calculate_S(SBox, input):
    row = 2 * int(input[0], 2) + int(input[5], 2)
    col = int(input[1:5], 2)
    return bin(SBox[row][col])[2:].zfill(4)


def exhaustive_attack_sbox(Sbox_name, R15, R15_fault, expected):
    
    res = []
    for key in range(64):
        bin_key = bin(key)[2:].zfill(6)

        out1 = calculate_S(Sboxes[Sbox_name], xor(R15, bin_key))
        out2 = calculate_S(Sboxes[Sbox_name], xor(R15_fault, bin_key))
        final_out = xor(out1, out2)
        
        if final_out == expected:
            res.append(bin_key)
    return res


def intersect(lists):

    res = lists[0]
    for i in range(1, len(lists)):
        if lists[i] == []:
            continue
        res = list(set(res) & set(lists[i]))
    return res