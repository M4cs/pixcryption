from uuid import uuid4
from pixcryption.core.lib import *
import os
import random
import string

if __name__ == "__main__":
  src_str = 'Hi my name is Max and this is an encrypted image that decrypts into a string. I call it pixelsafe encryption and plan on making it into an awesome thing.'

  if os.path.exists('user_key.png'):
    key_list = get_list_from_key('user_key.png')
  else:
    user_key, key_list = create_user_key(str(uuid4()))
    print("Run tests again to encrypt/decrypt test message.")
    os._exit(1)
  result, message = encrypt_w_user_key(key_list, src_str)
  if result:
    print('Encrypted Message Available At:', message)
  else:
    input("Program stopped by an error\nPress any key to continue....")
    os._exit(1)

  print('Decrypting...')
  result, message = decrypt_with_user_key('user_key.png', message)
  if result:
    print(message)
    print('Done!')
  else:
    input("Program stopped by an error\nPress any key to continue....")
    os._exit(1)
