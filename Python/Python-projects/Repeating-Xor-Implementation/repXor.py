#! /usr/bin/env python
from binascii import hexlify
from Crypto.Util.number import long_to_bytes
import math
""" Encrypting,Decrypting and Cracking of RepeatingXORin cryptography,I am still working on cracking it,having issues with getting the correct hamming length"""
class repeatingXOR:
      def __init__(self):
          self.counter = 0
      def encrypt(self,key: int,string: str):   
          enc_text = ""
          print(f"[+]Encrypting text with Repeating XOR")
          for ch in string:
              pkey = key[self.counter]
              character = chr(ord(ch) ^ ord(pkey))
              enc_text += character
              self.counter += 1
              if self.counter == len(key):
                 self.counter = 0   
          enc_text = hexlify(enc_text.encode())
          return f"[+]String: {string}|Enc-Text: \"{enc_text.decode()}\""
      def decrypt(self,enc_text:str,partial_key:str):
          #decoding the hex encrypted_text
          try:
             enc_text = bytes.fromhex(enc_text)
          except ValueError:
                 print("[+]Hex text not provided")
                 exit()
          #Creating  the key through a partial key text made by multiplying the key with the encrypted text and matching the partial key to the length of the text
          partial_key = partial_key * len(enc_text) 
          key = partial_key[:len(enc_text)]
          print("[+]Decrypting the encrypted text")
          dec_text = ''.join(chr(t ^ ord(k))for t,k in zip(enc_text,key))
          return f"[+]The decrypted text is \"{dec_text}\""
class crackRepXOR(repeatingXOR):
      def __init__(self,string):
          #Checking if it is hex or in bytes
          try:
             string = int(string,16)
             string = long_to_bytes(string)
             self.string = string
          except ValueError:
                 self.string = string
      #Wrong code,I left it there to preserve knowldge,Omoh!!!!
      @staticmethod    
      def chunk(string:str):
          pretesting_length = str(len(string)/2)
          #Testing if it contains .0
          if ".0" in pretesting_length:
              testing_length = int(pretesting_length.split(".")[0])
          #Assigning values without .0 to testing_length
          else:
              testing_length = float(pretesting_length)
          typ = str(type(testing_length))
          typ = typ.split("'")[1]
          match typ:
                case "int":
                     end1stBytes = testing_length
                     start2ndBytes = testing_length
                     end2ndBytes = len(string)
                     bytes1 = string[:end1stBytes]
                     bytes2 = string[start2ndBytes:end2ndBytes]
                     return (bytes1,bytes2);
                #Float case helps to split the excess character in the string 
                case "float":
                      length = str(testing_length)
                      end1stbytes = int(length.split(".")[0])
                      start2ndbytes = end1stbytes
                      end2ndbytes = len(string) - 1
                      excesschar_start = end2ndbytes
                      excesschar_end = end2ndbytes + 1
                      bytes1 = string[:end1stbytes]
                      bytes2 = string[start2ndbytes:end2ndbytes]
                      excess = string[excesschar_start:excesschar_end]
                      return(bytes1,bytes2,excess)
      @staticmethod
      def hammingscore(distance,byte1: bytes,byte2: bytes):
          #It is used to normalize the distance in relation to the total keylength and it can be derived by dividing the distance by the length of the shorter bytes bit <distance /(8*len(shorter_byte)>
          hammingscore = distance/(8*min(len(byte1),len(byte2)))
          return hammingscore
      @staticmethod
      def hamminglength(bytes1,bytes2):
          assert len(bytes1) == len(bytes2),"not equal"
          #Distance
          distance = 0
          for ch1,ch2 in zip(bytes1,bytes2):
              x = bin(ch1 ^ ch2)
              #checking for differing bits i.e setbits,the guy used Binary '&' to pick off the ones at the end and right shifts the one for Binary &  in a while loop checking if x is greater than 0,I used count() method,Omoh!!!
              set_bits = 0
              count = x.count('1')
              set_bits += int(count)
              #Adding the set_bits within a character to the distance
              distance += set_bits    
          return distance
      @staticmethod
      def chunktext(keylength:int,ciphertext: bytes) -> list:
          chunks = []
          start = 0
          end = start + keylength
          while (1):
                chunk1 = ciphertext[start:end]
                chunk2 = ciphertext[start + keylength:end+keylength]
                #Checking for the dangling bit that is lesser than the keylength
                if len(chunk1) < keylength:
                    break
                chunks.append(chunk1)
                if len(chunk2) < keylength:
                    break
                chunks.append(chunk2)
                #Create a new start and end
                start = end + keylength
                end = start + keylength
          return chunks
      def get_keylength(self):
          lowest = None
          best_length = None
          for keylength in range(2,math.ceil(len(self.string)/2)):
              to_average = []
              #Finding the chunks of a key
              chunks = crackRepXOR.chunktext(keylength,self.string)
              for i in range(0, len(chunks)):
                  for j in range(0,len(chunks)):

                      #Finding the average hamming score
                      if i == j:
                          pass
                      else:
                          distance = crackRepXOR.hamminglength(chunks[i],chunks[j])
                          score = crackRepXOR.hammingscore(distance,chunks[i],chunks[j])
                          #append the score
                          to_average.append(score)
              #Finding the average
              average = sum(to_average)/len(to_average)
              print(f"[+]The average hamming score for keylength:{keylength} is {average}")
              to_average = []
              #Finding the lowest key
              if lowest is None or average < lowest:
                 lowest,best_length = average,keylength
          print(f"[+]The best key_length is {best_length}")        
          return best_length
      def transpose_ciphertext(self,keylength:int) -> dict:
          ciphertext = self.string
          #Create a dictionary to contain the chunksand must be restricted to the keylength
          chunks = dict.fromkeys(range(keylength))
          i = 0
          #reading the ciphertext and assiging it to chunks,"octet" consists of 8 bits and a character is an octet in the sense that it contains 8 bits i.e 0000 0011
          for octet in ciphertext:
              #Checking if i is equal to keylength
              if (i == keylength):
                  i = 0
              #checking if chunks in dict is equal to None and assigning a list to it 
              if (chunks[i] == None):
                  chunks[i] = []
              #Appending the octet to the chunks
              chunks[i].append(octet)
              #increase the counter i
              i += 1
          #return the chunks
          return chunks
      def get_key(self):
          pass
if __name__ == "__main__":
   solve = repeatingXOR() 
   print(solve.encrypt("ENIGMA","CRAZY TING IN ACTION SHA")) 
   crack = crackRepXOR(b'\x06\x1c\x08\x1d\x14e\x1a\x00\t\ne\x07\x07g\x0c\x06\x1a\x00\x08\x03e\x1d\x01\x06')
   key = crack.get_keylength()
   print(crack.transpose_ciphertext(key))
