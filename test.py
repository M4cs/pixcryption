from uuid import uuid4
from pixcryption.core.lib import *
import os
import random
import string

if __name__ == "__main__":
    msg = 'Hi my name is Max and this is an encrypted image that decrypts into a string. I call it pixelsafe encryption and plan on making it into an awesome thing.'
    if os.path.exists('user_key.png'):
        key_list = get_list_from_key('user_key.png')
    else:
        user_key, key_list = create_user_key(str(uuid4()))
        print("Run tests again to encrypt/decrypt test message.")
        exit()
    result, message = encrypt_w_user_key(key_list, msg)
    if result:
      print('Encrypted Message Available At:', message)
    else:
      print('Error: {}'.format(message))
    print('Decrypting...')
    print(decrypt_with_user_key('user_key.png', message))
    print('Done!')