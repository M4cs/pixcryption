import numpy as np
from PIL import Image
from uuid import uuid4
from math import sqrt
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode
from base64 import b64decode
import itertools
import random
import os
import traceback

def byte_to_tuples(tuple_size, byte_string, fill_value=None):
  """
  This method converts a byte string into a list of tuples of integers
  """
  return list(itertools.zip_longest(*[iter(byte_string)]*tuple_size, fillvalue=fill_value))

def tuples_to_bytes(key_list):
  """
  This method converts a list of integers into a byte string
  """
  return bytes(key_list)

def extract_bytetuple(list_of_tuples, start, length):
  """
  This method breaks down the tuples in a list of tuples and returns a list of 
  of the first n number of integers from p, where;
  n = length, 16 for AES_key and mac and 15 for NONCE
  p = start, 0 for AES_key and NONCE and 15 for mac
  """
  bytelist = list(itertools.chain(*list_of_tuples))
  return bytelist[start:start+length]

def create_user_key(uuid):
  print('Preparing To Generate User Key (This may take a while but will only run once!)')
  allc = [i for i in itertools.product(range(256), repeat=3)]
  print('Complete...')
  print('Randomizing Base Key...')
  random.seed(uuid)
  random.shuffle(allc)
  print('Randomized...')
  print('Randomizing AES Key...')
  # Generating a cryptographically secure byte string of length 16
  AES_key = Random.get_random_bytes(AES.key_size[0])
  AESls = byte_to_tuples(3, AES_key, 0)
  print('Randomized...')
  max_it = 1114112
  w = int(sqrt(max_it)) + 1
  pixels = []
  key_list = [None] * max_it
  fresh = [None] * w
  count = 0
  total = 0
  print('Generating User Key...')
  for i in AESls:
  # Prepending the AES list (list of tuples of integers)
    fresh[count] = i
    count += 1
  for i in allc:
    if total == max_it:
      break
    if count == w:
      pixels.append(fresh)
      fresh = [None] * w
      count = 0
    fresh[count] = i
    key_list[total] = i
    count += 1
    total += 1
  array = np.array(pixels, dtype=np.uint8)
  new_image = Image.fromarray(array)
  new_image.save('user_key.png')
  print('Finished....')
  return pixels, key_list

def get_list_from_key(image_path):
  im = Image.open(image_path)
  return list(im.getdata())

def encrypt_w_user_key(key_list, source_string):
  # Converting the string into a byte string
  source_string = source_string.encode()
  try:
  # Generating a cryptographically secure byte string of length 15
    NONCE = Random.get_random_bytes(AES.block_size-1)
    NONCEls = byte_to_tuples(3, NONCE, 0)
    AES_key = tuples_to_bytes(extract_bytetuple(key_list, 0, 16))
    cipher = AES.new(AES_key, AES.MODE_OCB, NONCE)
    ciphertxt, mac = cipher.encrypt_and_digest(source_string)
    macls = byte_to_tuples(3, mac, 0)
  # ciphertxt is a byte string
    encrypted_string = b64encode(ciphertxt).decode()
  # ciphertext is encoded into another byte string and then decoded into a string
  except Exception as e:
    return False, e
  try:
    w = int(sqrt(len(encrypted_string))) + 1
    pixels = []
    fresh = [None] * w
    count = 0
    for i in NONCEls:
    # Prepending the NONCE list (list of tuples of integers)
      if count == w:
        pixels.append(fresh)
        fresh = [None] * w
        count = 0
      fresh[count] = i
      count += 1
    for i in macls:
    # Prepending the mac list (list of tuples of integers)
      if count == w:
        pixels.append(fresh)
        fresh = [None] * w
        count = 0
      fresh[count] = i
      count += 1
    for i in encrypted_string:
    # Grabbing a tuple from key_list's ord(i)th index for each character of src_string
      if count == w:
        pixels.append(fresh)
        fresh = [None] * w
        count = 0
      fresh[count] = key_list[ord(i)]
      count += 1
    pixels.append(fresh)

    while int(w - count) != 0:
    # Filling in the [None] tuples
      pixels[-1][count] = (0, 0, 0)
      count += 1

    array = np.array(pixels, dtype=np.uint8)
    uid = str(uuid4()).split('-')[0]
    new_image = Image.fromarray(array)
    new_image.save('enc_msg_{}.png'.format(uid))
    
    return True, 'enc_msg_{}.png'.format(uid)
  except Exception as e:
    traceback.print_exc()
    return False, ""
  
def decrypt_with_user_key(user_key, image_path):
  try:
    # get image pixels
    str_pixels = get_list_from_key(image_path)
    NONCE = tuples_to_bytes(extract_bytetuple(str_pixels, 0, 15))
    mac = tuples_to_bytes(extract_bytetuple(str_pixels, 15, 16))
    # get user pixels
    user_key_pixels = get_list_from_key(user_key)
    AES_key = tuples_to_bytes(extract_bytetuple(user_key_pixels, 0, 16))
    user_map = [None] * len(user_key_pixels)
    str_list = []
    skip = 0
    for i in str_pixels:
    # The first 11 tuples are for NONCE and mac
      if skip < 11:
        skip += 1
        continue
      if i != (0,0,0):
        str_list.append(chr(user_key_pixels.index(i)))

    # Undo what was done in encrypt
    encrypted_string = "".join(str_list)
    ciphertxt = b64decode(encrypted_string)
    cipher = AES.new(AES_key, AES.MODE_OCB, NONCE)

    return True, cipher.decrypt_and_verify(ciphertxt, mac).decode()
  except Exception as e:
    traceback.print_exc()
    return False, ""
