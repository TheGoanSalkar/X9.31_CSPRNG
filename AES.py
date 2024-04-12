import sys
from BitVector import *

class AES ():
    # class constructor - when creating an AES object , the
    # class ’s constructor is executed and instance variables
    # are initialized
    def __init__ (self , keyfile :str ) -> None :
        self.key = open(keyfile, "r").readlines()[0]
        self.keysize = len(self.key) * 8
        self.AES_modulus = BitVector(bitstring='100011011')

    
    def gen_key_schedule (self, key_bv):
        len_key_words = 60
        len_i = 8
        byte_sub_table = self.gen_subbytes_table()
        key_words = [None for i in range(len_key_words)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(len_i):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(len_i, len_key_words):
            if i % len_i == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-len_i] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words

    
    def gee(self, keyword, round_constant, byte_sub_table):
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant

    
    def gen_subbytes_table(self):
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable


    def gen_keys(self, key_bv):
        key_words = self.gen_key_schedule(key_bv)
        key_schedule = []
        for word in key_words:
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            key_schedule.append(keyword_in_ints)
        num_rounds = 14
        round_keys = [None for i in range(num_rounds+1)]
        for i in range(num_rounds+1):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + key_words[i*4+3]).get_bitvector_in_hex()
        return round_keys
    

    def sub_Bytes(self, bitvec, subBytesTable):
        for i in range(16):
            sub_bitvec = bitvec[i*8:i*8 + 8]
            [LE, RE] = sub_bitvec.divide_into_two()
            LE = int(LE)
            RE = int(RE)
            sub_byte = subBytesTable[LE*16 + RE]
            sub_byte = BitVector(intVal = sub_byte, size = 8)
            bitvec = bitvec[0:i*8] + sub_byte + bitvec[i*8 + 8:]
        return bitvec
    
    def shift_Rows(self, bitvec):
        bitvec = [[bitvec[j*32 + i*8:j*32 + i*8 + 8] for i in range(4)] for j in range(4)]
        bitvec = [[row[i] for row in bitvec] for i in range(len(bitvec[0]))]
        bitvec[0] = [bitvec[0][0], bitvec[0][1], bitvec[0][2], bitvec[0][3]]
        bitvec[1] = [bitvec[1][1], bitvec[1][2], bitvec[1][3], bitvec[1][0]]
        bitvec[2] = [bitvec[2][2], bitvec[2][3], bitvec[2][0], bitvec[2][1]]
        bitvec[3] = [bitvec[3][3], bitvec[3][0], bitvec[3][1], bitvec[3][2]]
        return bitvec
    

    def mix_Columns(self, bitvec):
        bitvec2 = [[None for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                a = bitvec[j][i]
                b = bitvec[(j + 1) % 4][i]
                c = bitvec[(j + 2) % 4][i]
                d = bitvec[(j + 3) % 4][i]
                two = BitVector(bitstring = '00000010')
                three = BitVector(bitstring = '00000011')
                bitvec2[j][i] = (a.gf_multiply_modular(two, self.AES_modulus, 8) ^ b.gf_multiply_modular(three, self.AES_modulus, 8)) ^ (c ^ d) 
        return bitvec2
    

    def ctr_aes_image (self , iv , image_file , enc_image ):
        """
        Inputs :
        iv ( BitVector ): 128 - bit initialization vector
        image_file (str): input .ppm file name
        enc_image (str): output .ppm file name
        Method Description :
        * This method encrypts the contents in image_file using CTR mode AES and writes the encrypted content to enc_image
        * Method returns void
        """
        img_bv = BitVector(filename = image_file)
        key_bv = BitVector(textstring = self.key)

        # Extracting image header
        f1 = open(image_file, "rb")
        lines = f1.readlines()
        f1.close()
        f2 = open("image_without_header.ppm", "wb")
        for line in lines[3:]:
            f2.write(line)
        f2.close()
        header = (lines[0] + lines[1] + lines[2]).decode('ascii')
        header_bv = BitVector(textstring = header)

        img_bv = BitVector(filename = "image_without_header.ppm")
        
        f = open(enc_image, "wb")
        header_bv.write_to_file(f)
        
        # Generating Key Schedule
        round_keys = self.gen_keys(key_bv)
        
        # Generating Sub Bytes Table
        subBytesTable = self.gen_subbytes_table()
        
        len_iv = len(iv)
        num_rounds = 14
        while (img_bv.more_to_read):
            bitvec_img = img_bv.read_bits_from_file( 128 )
            if len(bitvec_img) < 128:
                bitvec_img.pad_from_right(128 - len(bitvec_img))
            if bitvec_img._getsize() > 0:
                bitvec = iv

                print(bitvec.get_bitvector_in_hex())

                # Add Round Key
                bitvec ^= BitVector(hexstring = round_keys[0])
                
                for round_count in range(num_rounds):
                    # Substitute Bytes Step
                    bitvec = self.sub_Bytes(bitvec, subBytesTable)
                    
                    # Shift Rows Step
                    bitvec = self.shift_Rows(bitvec)

                    transform_bitVec = BitVector(size = 0)
                    for i in range(4):
                        for j in range(4):
                            transform_bitVec += bitvec[j][i]
                    
                    # Mix Columns Step
                    if round_count != num_rounds - 1:
                        bitvec = self.mix_Columns(bitvec)
                        
                        transform_bitVec = BitVector(size = 0)
                        for i in range(4):
                            for j in range(4):
                                transform_bitVec += bitvec[j][i]

                    # Adding Round Key
                    transform_bitVec ^= BitVector(hexstring = round_keys[round_count + 1])
                    bitvec = transform_bitVec
    
                temp = bitvec_img ^ bitvec
                temp.write_to_file(f)  
                int_iv = (int(iv) + 1) % (2**len_iv)
                iv = BitVector(intVal = int_iv, size=128)
        f.close()


    def ede(self, subBytesTable, round_keys, bitvec):
        num_rounds = 14
        for round_count in range(num_rounds):
            # Substitute Bytes Step
            bitvec = self.sub_Bytes(bitvec, subBytesTable)
            
            # Shift Rows Step
            bitvec = self.shift_Rows(bitvec)

            transform_bitVec = BitVector(size = 0)
            for i in range(4):
                for j in range(4):
                    transform_bitVec += bitvec[j][i]
            
            # Mix Columns Step
            if round_count != num_rounds - 1:
                bitvec = self.mix_Columns(bitvec)
                
                transform_bitVec = BitVector(size = 0)
                for i in range(4):
                    for j in range(4):
                        transform_bitVec += bitvec[j][i]

            # Adding Round Key
            transform_bitVec ^= BitVector(hexstring = round_keys[round_count + 1])
            bitvec = transform_bitVec
        return bitvec


    def x931 (self , v0 , dt , totalNum , outfile ):
        """
        Inputs :
        v0 ( BitVector ): 128 - bit seed value
        dt ( BitVector ): 128 - bit date / time value
        totalNum (int): total number of pseudo - random numbers to generate
        Method Description :
        * This method uses the arguments with the X9.31 algorithm to compute totalNum number of pseudo - random numbers , each represented as BitVector objects .
        * These numbers are then written to the output file in base 10 notation .
        * Method returns void
        """
        key_bv = BitVector(textstring = self.key)

        # Generating Key Schedule
        round_keys = self.gen_keys(key_bv)
        
        # Generating Sub Bytes Table
        subBytesTable = self.gen_subbytes_table()
        
        for i in range(totalNum):
            # AES Encrypting the Date-Time Vector
            bitvec = dt ^ BitVector(hexstring = round_keys[0])
            bitvec = self.ede(subBytesTable, round_keys, bitvec)
                
            # Obtaining random number and writing to file
            dtEDE_xor_v = bitvec ^ v0
            # Add Round Key
            rand_bitvec = dtEDE_xor_v ^ BitVector(hexstring = round_keys[0])    
            # Round-Based Processing
            rand_bitvec = self.ede(subBytesTable, round_keys, rand_bitvec)
            randNum = str(int(rand_bitvec))
            f = open(outfile, "a")
            f.write(randNum + '\n')
            f.close()

            # Generating new initialization vector
            v0 = rand_bitvec ^ bitvec
            # Add Round Key
            v0 ^= BitVector(hexstring = round_keys[0])
            # Round-Based Processing
            v0 = self.ede(subBytesTable, round_keys, v0)


if __name__ == "__main__":
    cipher = AES( keyfile = sys. argv [3])
    if sys. argv [1] == "-e":
        cipher . encrypt ( plaintext = sys. argv [2], ciphertext = sys . argv [4])
    elif sys . argv [1] == "-d":
        cipher . decrypt ( ciphertext = sys. argv [2], recovered_plaintext =sys . argv [4])
    elif sys . argv [1] == "-i":
        cipher . ctr_aes_image (iv= BitVector ( textstring = "counter-mode-ctr"), image_file =sys. argv [2], enc_image =sys. argv [4])
    else :
        cipher . x931 (v0= BitVector ( textstring = "counter-mode-ctr"), dt= BitVector ( intVal = 501 , size = 128), 
                       totalNum = int (sys . argv [2]), outfile = sys . argv [4])