from PIL import Image
import numpy as np
from uuid import uuid4
from math import sqrt
import time
import itertools
import random

def create_user_key(uuid):
  print('Preparing To Generate User Key (This may take a while but will only run once!)')
  allc = [i for i in itertools.product(range(256), repeat=3)]
  print('Complete...')
  print('Randomizing Base Key...')
  random.seed(uuid)
  random.shuffle(allc)
  print('Randomized...')
  max_it = 1114112
  w = int( 1114112 / sqrt(1114112)) + 1
  pixels = []
  key_list = [None] * 1114112
  fresh = [None] * w
  count = 0
  total = 0
  print('Generating User Key...')
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

def encrypt_w_user_key(key_list, string):
  try:
    w = int(len(string) / sqrt(len(string))) + 1
    pixels = []
    fresh = []
    for i in string:
        if len(fresh) == w:
            pixels.append(fresh)
            fresh = []
        fresh.append(key_list[ord(i)])
    pixels.append(fresh)

    if len(pixels[-1]) != w:
        num_left = int(w - len(pixels[-1]))
        count = 0
        while count < num_left:
            pixels[-1].append((0, 0, 0))
            count += 1

    array = np.array(pixels, dtype=np.uint8)
    uid = str(uuid4()).split('-')[0]
    new_image = Image.fromarray(array)
    new_image.save('enc_msg_{}.png'.format(uid))
    return True, 'enc_msg_{}.png'.format(uid)
  except Exception as e:
    return False, e
  
def decrypt_with_user_key(user_key, image_path):
  try:
    # get image pixels
    str_pixels = get_list_from_key(image_path)
    # get user pixels
    user_key_pixels = get_list_from_key(user_key)
    user_map = [None] * len(user_key_pixels)
    str_list = []
    for i in str_pixels:
      if i != (0,0,0):
        str_list.append(chr(user_key_pixels.index(i)))
    print("".join(str_list))
    
  except Exception as e:
    print(e)
