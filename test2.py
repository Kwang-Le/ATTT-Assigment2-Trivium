#Trivium
from collections import deque



def main():
    initialization_vector = 0x1B3A543C9A5DC67A3F4C # IV 80 bits, 20 byte * 4
    key = 0x5DC67A3F4C1B3A543C9A # key 80 bits, 20 byte * 4

    state = []  #initial state including 3 registers A, B and C of trivium

    plain_file = open("./03streamcipher.pdf", "rb")
    plain_file_binary = plain_file.read()

    encrypt_or_decrypt = 1 # 0 for encrypt and 1 for decrypt

    keystream = []
    cipher = []
    # convert msg to bit
    # bit_msg = bytes_to_bits(plain_file_binary) 

    # convert hex to bit
    bit_iv = format(initialization_vector, '0>80b') 
    bit_key = format(key, '0>80b')

    plain_file_bit = bytes_to_bits(plain_file_binary)

    #register A
    state += [*bit_iv] #80 bits of IV is loaded into leftmost locations of register A
    state += ['0' for _ in range(93 - 80)]

    #register B
    state += [*bit_key] #80 bits of key is loaded into leftmost locations of register B
    state += ['0' for _ in range(84 - 80)]

    #register C
    state += ['0' for _ in range(108)] # all the other bits are 0
    state += ['1' for _ in range(3)] # except the three last bits in register C which are 1
    
    state = deque(state)

    #clock 1152 time
    for i in range(1152):
        output_bit, state = gen_keystream(state)
    #generate keystream
    for i in range(len(plain_file_bit)):
        output_bit, state = gen_keystream(state)
        keystream.append(output_bit)
        # create cipher text
        if encrypt_or_decrypt == 0:
            cipher.append(str(output_bit ^ int(plain_file_bit[i])))
    
    # write encyption to file
    if encrypt_or_decrypt == 0:
        with open('./03streamcipher.pdf', 'wb') as encrypted_file:
            encrypted_file.write(text_from_bits("".join(cipher)))

    # decrypt
    if encrypt_or_decrypt == 1:
        plain_text_bit_array = []
        for i in range(len(plain_file_bit)):
            plain_text_bit_array.append(str(int(plain_file_bit[i]) ^ keystream[i]))
    
        plain_text = text_from_bits("".join(plain_text_bit_array)) 

        with open('./03streamcipher.pdf', 'wb') as dec_file:
            dec_file.write(plain_text)




def gen_keystream(state):
    t1 = int(state[65]) ^  int(state[92]) # state[66] xor state[93] minus 1 because count from 0
    t2 = int(state[161]) ^  int(state[176])
    t3 = int(state[242]) ^  int(state[287])

    output_bit = t1 ^ t2 ^ t3

    t1 = t1 ^ (int(state[90]) & int(state[91])) ^ int(state[170])
    t2 = t2 ^ (int(state[174]) & int(state[175])) ^ int(state[263])
    t3 = t3 ^ (int(state[285]) & int(state[286])) ^ int(state[68])

    # right shift 1
    state.rotate()

    state[0] = str(t3) 
    state[93] = str(t1)
    state[177] = str(t2)

    return output_bit, state

def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def bytes_to_bits(bytes, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int.from_bytes(bytes, 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')



main()