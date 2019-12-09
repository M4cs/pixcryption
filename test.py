from uuid import uuid4
from pixcryption.core.lib import *
import os
import random
import string

def test_decryption_works_fuzzy():
    msg = "".join(random.choice(string.ascii_letters) for _ in range(random.randint(1, 100)))
    if os.path.exists('user_key.png'):
        key_list = get_list_from_key('user_key.png')
    else:
        user_key, key_list = create_user_key(str(uuid4()))
    result, message = encrypt_w_user_key(key_list, msg)
    if not result:
      print('Error: {}'.format(message))
    print('Decrypting...')
    decrypted_msg = decrypt_with_user_key('user_key.png', message)
    if decrypted_msg != msg:
      raise ValueError(f"Decrypted message does not equal original message ({decrypted_msg} != {msg})")
    else:
      print(f"Decryption was sucessful.\n({decrypted_msg} == {msg})")

if __name__ == "__main__":
    msg = 'Hi my name is Max and this is an encrypted image that decrypts into a string. I call it pixelsafe encryption and plan on making it into an awesome thing.'
    if os.path.exists('user_key.png'):
        key_list = get_list_from_key('user_key.png')
    else:
        user_key, key_list = create_user_key(str(uuid4()))
    result, message = encrypt_w_user_key(key_list, msg)
    if result:
      print('Encrypted Message Available At:', message)
    else:
      print('Error: {}'.format(message))
    print('Decrypting...')
    print(decrypt_with_user_key('user_key.png', message))
    print('Done!')

    test_decryption_works_fuzzy()
