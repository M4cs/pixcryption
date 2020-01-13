from uuid import uuid4
from pixcryption.core.lib import *
import os

if __name__ == "__main__":
    src_str = 'Hi my name is Max and this is an encrypted image that decrypts into a string. I call it pixelsafe encryption and plan on making it into an awesome thing.'

    if not os.path.exists('user_key.png'):
        create_user_key(str(uuid4()))
        print("Run tests again to encrypt/decrypt test message.")
        os._exit(1)
    result, encrypted_img_path = encrypt_w_user_key('user_key.png', 'image.jpg', src_str)
    if result:
        print('Encrypted Message Available At:', encrypted_img_path)
    else:
        input("Program stopped by an error\nPress any key to continue....")
        os._exit(1)

    print('Decrypting...')
    result, decrypted_str = decrypt_with_user_key('user_key.png', encrypted_img_path, 'image.jpg')
    if result:
        print(decrypted_str)
        print('Done!')
    else:
        input("Program stopped by an error\nPress any key to continue....")
        os._exit(1)
