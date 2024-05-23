from bs4 import BeautifulSoup
import requests
from functions import PC1, PC2
from inputs import *
import K16_recovery


def replace_x_bits(partial_K, val):

    val = bin(val)[2:].zfill(8)  #to delete 0b
    partial_K = list(partial_K)
    j = 0
    for i in [8, 17, 21, 24, 34, 37, 42, 53]:      #on a demmarer de 0 donc les bits de parite sont -1
        partial_K[i] = val[j]
        j += 1
    partial_K = "".join(partial_K)
    return partial_K


def add_parity_bits(partial_K):

    partial_K = list(partial_K)
    to_add = []
    sum_=int(partial_K[0], 2)
    j = 1
    for i in range(1, 56):
        sum_ += int(partial_K[i], 2)            #extract the octects to know the parity bit to add
        j += 1
        if j == 7:
            j = 0
            if sum_ % 2 == 0:
                to_add.append('1')
            else:
                to_add.append('0')
            sum_ = 0
    
    
    # Adding the parity bits
    for i in [7, 15, 23, 31, 39, 47, 55, 63]:
        partial_K.insert(i, to_add[j])
        j += 1
    
    partial_K = "".join(partial_K)
    return partial_K


def reverse_PC2(K16):
    K = ''
    pos_to_determine = [9, 18, 22, 25, 35, 38, 43, 54]  # The unknown bits posisitions after reversing PC2
    for i in range(56):
        if i + 1 not in pos_to_determine:
            K += K16[PC2.index(i + 1)]
        else:
            K+= 'x'
    return K


def reverse_PC1(partial_K):

    K = ''
    for i in range(64):
        if (i + 1) % 8 != 0:                   # la place des cles de parity 
            K += partial_K[PC1.index(i + 1)]
    return K


def recover_K(K16):
 
    K = reverse_PC2(K16)                             
    expected_output = str(plaintext)[2:].upper() 
    
    # The parameters for the URL
    iv = '&iv=0000000000000000'
    input = '&input=' + str(cipher_corr)[2:].upper()    # The correct ciphertext
    mode = '&mode=ecb'
    action = '&action=Decrypt'
    output = '&output='
    
    for i in range(256):                #starting the brute-force
        key1 = replace_x_bits(K, i)
        key2 = reverse_PC1(key1)
        key3 = add_parity_bits(key2)

        key4 = hex(int(key3, 2))[2:].upper()
        url = "https://emvlab.org/descalc/?"      # The base URL to the DES calculator
        url += 'key=' + key4 + iv + input + mode + action + output   # The final request

        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        if expected_output == soup.find(id='output').getText():
            print("-----------------------------------------------------------------------------------------------")
            print("\t\t\t\tTHE KEEEEYYYY : " + key4)
            print("-----------------------------------------------------------------------------------------------")

            return
    
    print("Unfortunately ! no key found")
        
def main():
    recover_K(K16_recovery.K16_recovery())


if __name__ == "__main__":
    main()