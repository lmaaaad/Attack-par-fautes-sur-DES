from functions import *
from inputs import *
def K16_recovery():
  
    # The possible key_parts found for each S-box input
    possible_keys_part = {
        "S1" : [],
        "S2" : [],
        "S3" : [],
        "S4" : [],
        "S5" : [],
        "S6" : [],
        "S7" : [],
        "S8" : []
    }

    R16, L16 = get_R16_L16(cipher_corr) # R16 and L16 registers from correct ciphertext
    R15 = L16                           # According to equations R15 = L16
    R15_expanded = expand(R15)          # Expansion of R15 to 48 bits
    k=1
    for faulted_cipher in cipher_fault:
        print ("\n-------------------------------- Cipher fault num ",k,"------------------------------------------" )
        R16_err, L16_err = get_R16_L16(faulted_cipher)  # R16 and L16 registers from faulted ciphertext
        R15_err = L16_err
        R15_err_expanded = expand(R15_err)

        R16_xor_R16err = xor(R16, R16_err)              # R16 xor R16_err
        revP_R16_xor_R16err = rev_perm(R16_xor_R16err)  # P^-1(R16 xor R16_err)

        equations = []      # The equations we must solve
        for i in range(0, 32, 4):
            equations.append(revP_R16_xor_R16err[i:i+4])

        print("\nEquations for S-boxes:")
        for i, eq in enumerate(equations):
            print(f"S{i+1} equation:", eq)

        for i in range(8):  # Exhaustive search on K16 subparts possible values
            if equations[i] == '0000':
                continue
            sbox_name = 'S' + str(i + 1)
            result = exhaustive_attack_sbox(sbox_name, R15_expanded[i*6:(i+1)*6], R15_err_expanded[i*6:(i+1)*6], equations[i])
            if result != []:
                possible_keys_part[sbox_name].append(result)
        k=k+1        
        print("-----------------------------------------------------------------------------------------------")


    for key in list(possible_keys_part.keys()):
        possible_keys_part[key] = intersect(possible_keys_part[key])

    print("\nPossible key parts for each S-box:")
    for key, parts in possible_keys_part.items():
        print(f"{key}: {parts}")

    # Recovery of K16
    K16 = ''
    for part in possible_keys_part.values():
        K16 += part[0]
    K16_hex=hex(int(K16, 2))[2:].upper()
    print("\nRecovered K16 key: \n",K16, "(Binaire) \n" , K16_hex, "(hex)" )    
    return K16

def main():
    # Call the K16 recovery function
    K16_recovery()

if __name__ == "__main__":
    main()