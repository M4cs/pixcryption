import numpy as np
from PIL import Image
from uuid import uuid4
from math import sqrt, floor
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode
from base64 import b64decode
import itertools
import random
import os
import traceback

"""
The primary method by which this program works is:-

  1) A list of definite size is created, this is referred to as fresh

     The size of this list is dependent on external factors such as string length

  2) A fixed list is taken and it is iterated through, adding in each item from 
     this list to fresh, until either fresh is filled or the list is exhausted

     What this list will contain also depends on external factors such as the string 
     itself

  3) This process ultimately fills up another object, pixels, which is a list of list of 
     tuples
     
     This pixels object is turned into an array using numpy and an image is created
"""

def byte_to_tuples(tuple_size, byte_string, fill_value=None):
    """
    This function converts a byte string into a list of tuples of integers
    """
    return list(itertools.zip_longest(*[iter(byte_string)]*tuple_size, fillvalue=fill_value))

def extract_bytes_from_tuple(list_of_tuples, start, length):
    """
    This function breaks down the tuples in a list of tuples and returns a list of 
    of the first n number of integers from p, where;

    n = length, 16 for AES_key and mac and 15 for NONCE;
    p = start, 0 for AES_key and NONCE and 16 for mac;

    Then it converts the list of integers into a byte string and returns it
    """
    bytelist = list(itertools.chain(*list_of_tuples))
    return bytes(bytelist[start:start+length])

def generate_random_pixelTuple(backlog):
    """
    This is an algorithm that can predict any tuple in the cartesian product of
    4 lists of range(0, 256), given its index. This cartesian product is the same as 
    `list(itertools.product(range(0, 256), repeat=4))`

    It generates a random integer that hasn't already been used before and predicts
    the tuple that exists in that index of the cartesian product
    """
    upper_limit = 256**4
    index = random.randint(0, upper_limit)
    while index in backlog:
        index = random.randint(0, upper_limit)
  
    red = floor(index/256**3)
    green = floor(index%256**3/256**2)
    blue = floor(index%256**2/256)
    alpha = index%256**2%256
    return (red, green, blue, alpha), index

def binary_diff(list1, list2):
    diff = []
    slice_and_check(list1, list2, diff)
    return diff

def slice_and_check(list1, list2, diff):
    half = floor(len(list1)/2)
    left_list1 = list1[:half]
    left_list2 = list2[:half]
    right_list1 = list1[half:]
    right_list2 = list2[half:]
    if not left_list1 == left_list2:
        if len(list1) is 1:
            diff.append(list1[0])
        else:
            slice_and_check(left_list1, left_list2, diff)
    if not right_list1 == right_list2:
        if len(list1) is 1:
            diff.append(list1[0])
        else:
            slice_and_check(right_list1, right_list2, diff)

def get_list_from_image(image_path):
    if not os.path.exists(image_path):
        raise Exception("Couldn't find image at given path")
        os._exit(1)
    im = Image.open(image_path)
    if im.mode == 'RGB':
        im = im.convert('RGBA')
    return list(im.getdata())

def get_list_of_lists_from_image(image_path):
    if not os.path.exists(image_path):
        raise Exception("Couldn't find image at given path")
        os._exit(1)
    im = Image.open(image_path)
    if im.mode == 'RGB':
        im = im.convert('RGBA')
    im = np.asarray(im)
    return im.tolist()

def create_user_key(uuid):
    """
    This function creates a user_key, this is only created once

    The user_key is different for each time it is created
    The values that are different for each user_key is the AES_key itself 
    and the shuffled pixel tuples

    The AES_key list is added in first, the tuples in allc follow afterwards
    The resulting pixel array is used to create the user_key img
    """
    print('Preparing To Generate User Key (This may take a while but will only run once!)')
    print('Randomizing Base Key...')
    random.seed(uuid)
    print('Randomized...')
    print('Randomizing AES Key...')
    # Generating a cryptographically secure byte string of length 16
    AES_key = Random.get_random_bytes(AES.key_size[0])
    AESls = byte_to_tuples(4, AES_key, 0)
    print('Randomized...')
    #1114112 is the code point for unicode chars
    max_it = 1114112
    w = int(sqrt(max_it)) + 1
    pixels = []
    backlog = set()
    fresh = [None] * w
    count = 0
    total = 0
    print('Generating User Key...')
    for i in AESls:
        # Prepending the AES list (list of tuples of integers)
        fresh[count] = i
        count += 1
        total += 1
    while total < max_it:
        if count == w:
            pixels.append(fresh)
            fresh = [None] * w
            count = 0
        fresh[count], index = generate_random_pixelTuple(backlog)
        backlog.add(index)
        count += 1
        total += 1

    array = np.array(pixels, dtype = np.uint8)
    new_image = Image.fromarray(array, 'RGBA')
    new_image.save('user_key.png')
    print('Finished....')

def encrypt_w_user_key(user_key, target_img, source_string):
    """
    This function works in multiple steps:-

    1) The source string is converted into a byte string
    2) A NONCE is generated and the AES_key is retrieved from user_key img
    3) A list is generated called NONCEls, this just a list of tuples form of NONCE
    4) The source_string is encrypted in AES OCB mode, which returns the mac byte 
        string
    5) macls is created in the same method as NONCEls
    6) The encrypted string is encoded with b64 and converted into a string 
        (from byte_string)
    7) NONCEls, macls and the appropriate keys for each string char is stored 
        sequentially
    8) Any Empty tuples in the final fresh (list) is filled with (0, 0, 0)
    9) An image is created with the array of pixels
    10) Finally, the name of the encrypted message image is returned
    """
    # Converting the string into a byte string
    source_string = source_string.encode()
    key_list = get_list_from_image(user_key)
    try:
    # Generating a cryptographically secure byte string of length 15
        NONCE = Random.get_random_bytes(AES.block_size-1)
        NONCEls = byte_to_tuples(4, NONCE, 0)
        AES_key = extract_bytes_from_tuple(key_list, 0, 16)
        cipher = AES.new(AES_key, AES.MODE_OCB, NONCE)
        ciphertxt, MAC = cipher.encrypt_and_digest(source_string)
        MACls = byte_to_tuples(4, MAC, 0)
    # ciphertxt is a byte string
        encrypted_string = b64encode(ciphertxt).decode()
    # ciphertext is encoded into another byte string and then decoded into a string
    except Exception as e:
        traceback.print_exc()
        return False, e
    try:
        pixels = []
        count = 0
        for i in NONCEls:
        # Prepending the NONCE list (list of tuples of integers)
            pixels.append(i)
            count += 1
        for i in MACls:
        # Prepending the mac list (list of tuples of integers)
            pixels.append(i)
            count += 1
        for i in encrypted_string:
        # Grabbing a tuple from key_list's ord(i)th index for each character of src_string
            pixels.append(key_list[ord(i)])
            count += 1

        img_pixels = get_list_of_lists_from_image(target_img)
        w = len(img_pixels[0])
        k = 0
        for i in range(0, len(pixels)):
            img_pixels[floor(i/w)][i%w] = list(pixels[i])

        array = np.array(img_pixels, dtype=np.uint8)
        uid = str(uuid4()).split('-')[0]
        new_image = Image.fromarray(array, 'RGBA')
        new_image.save('enc_msg_{}.png'.format(uid))

        return True, 'enc_msg_{}.png'.format(uid)
    except Exception as e:
        traceback.print_exc()
        return False, ""

def decrypt_with_user_key(user_key, encrypted_image_path, original_image_path):
    """
    This function works in multiple steps:-

    1) The NONCE and mac are extracted from the list of pixel tuples in 
        encrypted string img
    2) The AES_key is retrieved from user_key img
    3) Key_tuples are looked up and their indexes are used to return a 
        character accordingly
    4) The resulting list is then turned into a string and decoded with b64
    5) This string is now decrypted using AES and verified using the mac
    6) Finally, the resulting string is returned
    """
    try:
        # get image pixels
        encrypted_pixels = get_list_from_image(encrypted_image_path)
        original_pixels = get_list_from_image(original_image_path)
        diffls = binary_diff(encrypted_pixels, original_pixels)
        final_index = len(diffls)
        NONCE = extract_bytes_from_tuple(encrypted_pixels, 0, 15)
        MAC = extract_bytes_from_tuple(encrypted_pixels, 16, 16)
        # get user pixels
        user_key_pixels = get_list_from_image(user_key)
        AES_key = extract_bytes_from_tuple(user_key_pixels, 0, 16)
        user_map = [None] * len(user_key_pixels)
        str_list = []
        for i in range(8, final_index):
            if i != (0, 0, 0, 0):
                str_list.append(chr(user_key_pixels.index(encrypted_pixels[i])))

        # Undo what was done in encrypt
        encrypted_string = "".join(str_list)
        ciphertxt = b64decode(encrypted_string)
        cipher = AES.new(AES_key, AES.MODE_OCB, NONCE)
        source_string = cipher.decrypt_and_verify(ciphertxt, MAC).decode()

        return True, source_string
    except Exception as e:
        traceback.print_exc()
        return False, ""
