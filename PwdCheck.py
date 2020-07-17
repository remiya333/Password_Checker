import requests
import hashlib
import sys

'''
This Code checks whether a given password is hacked or not using a api which returns the number of times a password is hacked.
The passwords to be checked is inputted from the commandline.
'''

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError('Error fetching check the api and try again')
        #print(res.text)
    return res

def get_password_leaks_count(hashes, hash_to_check):
    #print(response.text)
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0



def pawd_api_check(password):
    #check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5],sha1password[5:]
    response = request_api_data(first5_char)
    #print(first5_char,tail)
    return get_password_leaks_count(response,tail)


def main(args):
    for password in args:
        count = pawd_api_check(password)
        if count:
            print(password +' was found ' + count + ' times.....you should change the password')
        else:
            print(password +'was not found')


    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))


