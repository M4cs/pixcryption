# Pixcryption
Pixel Safe Encryption - Currently in Development

[![Stars](https://img.shields.io/github/issues/M4cs/pixcryption)]

# Goal

Pixcryption's goal is to offer a new form of steganography/encryption through imagery. It uses a random seeded UUID to generate a user_key which matches RGB perfect values to match to unicode characters. These are stored in a `user_key.png` file which is used to encrypt and decrypt messages. The speed is getting there but there is 100% room for improvement. I have been working on this for 2 months and BY NO MEANS IS THIS A SECURE SOLUTION YET. It has Pretty Good Security but I'm sure there are plenty of flaws to be found. 

[![Run on Repl.it](https://repl.it/badge/github/M4cs/pixcryption)](https://repl.it/github/M4cs/pixcryption)

# Requirements

- Python 3.6+
- Pillow
- Numpy

# Usage

Inside of the `core.lib` module you will find all functions currently used in the project.

With these you can generate a user key, grab a key_list from a user key, and encrypt/decrypt messages. The implementation is pretty simple and you can take a look at `test.py` for an example.

**This only encrypts unicode characters at the moment which makes it a good choice for messaging. The # of pixels in the image will be == to the # of characters in the string encrypted. This is one security flaw which we need to look into fixing.**

# Contribution

If you would like to contribute to pixcryption please submit a pull request. Any help is welcome and all PRs will be reviewed.
