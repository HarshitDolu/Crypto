
from django.shortcuts import render,redirect
from .models import contact,User
from django.core.mail import send_mail                                   # mail sending
from django.conf import settings
from django.http import HttpResponse
# Create your views here.
from django.contrib import messages
from django.db.models import Q

# for captcha
import requests
import json
# Home view
def home(request):
    num_visits = request.session.get('num_visits', 0);
    request.session['num_visits'] = num_visits + 1

    ### For IP Address
    def get_ip(request):
        adress = request.META.get('HTTP_X_FORWARDED_FOR')
        if adress:
            ip = adress.split(',')[-1].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    ip = get_ip(request)
    u = User(user=ip)
    result = User.objects.filter(Q(user__icontains=ip))
    if len(result) == 1:
        pass
    elif len(result) > 1:
        pass
    else:
        u.save()
        # unique user
    count = User.objects.all().count()
    context = {'num_visits': num_visits, 'count': count}

    if request.method=='POST' and 'sent' in request.POST:
        name=request.POST['name']
        email=request.POST['email']
        subject=request.POST['subject']
        message=request.POST['message']

        if name=='' or email=='' or subject=='' or message=='':
            messages.success(request, "Hey Cryptogeek, Please fill up all the fields ")
        else:



            #recaptcha stuff
            clientKey=request.POST['g-recaptcha-response']
            secretKey='6Ld3K9oZAAAAAPj6_q-PcTDn2hbtNyA6_2K4XkIi'

            captcha_data={
                'secret':secretKey,
                'response':clientKey
            }
            r=requests.post('https://www.google.com/recaptcha/api/siteverify',data=captcha_data)
            response=json.loads(r.text)
            verify=response['success']
            if verify:
                ask = contact(name=name, email=email, subject=subject, message=message)
                ask.save()
                messages.success(request, "Hey Cryptogeek, Thank You for your valuable Feedback ")
                send_mail('CIPHERX',
                          'Thank You for your valuable Feedback! We really appreciate you taking the time out to share your experience with us. We will reach to you soon.\n Thanks & Regards \n- Cipherx Team.  '
                          , settings.EMAIL_HOST_USER,
                          [email], fail_silently=False
                          )
            else:
                messages.success(request, "Hey Cryptogeek, Please check the captcha ")







    return render(request,'attack/home.html',context)
# encrypt function of k-shift cipher
def remove(string):
    return "".join(string.split())
def encrypt(text, s):
    result = ""

    # traverse text
    for i in range(len(text)):
        char = text[i]

        # Encrypt uppercase characters
        if (char.isupper()):
            result += chr((ord(char) + s - 65) % 26 + 65)

            # Encrypt lowercase characters
        else:
            result += chr((ord(char) + s - 97) % 26 + 97)

    return result

    # traverse text


def decrypt(text, s):
    result = ""

    # traverse text
    for i in range(len(text)):
        char = text[i]

        # Encrypt uppercase characters
        if (char.isupper()):
            result += chr((ord(char) - s - 65) % 26 + 65)

            # Encrypt lowercase characters
        else:
            result += chr((ord(char) - s - 97) % 26 + 97)

    return result


def kshift(request):
    if request.method == 'POST' and 'enc' in request.POST:

        # get post parameters of encryption

        plaintext= request.POST['plaintext']
        key1= request.POST['key']
        if key1 == '' or plaintext == '':
            messages.warning(request, "Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            plaintext=remove(plaintext)

            plaintext=plaintext.upper()

            key1 = int(key1)

            # get post parameters for decryption
            result = encrypt(plaintext, key1)
            context={'plainText':plaintext,'Key':key1,'result':result}
            key1=str(key1)
            messages.success(request,'plainText'+'='+plaintext+'    '+'Key'+'='+key1+'    '+'CipherText'+'='+result)
            return render(request,'attack/kshift.html',context)
            #print(result)

    if request.method=='POST' and 'dec' in request.POST:
        ciphertext=request.POST['ciphertext']
        key2=request.POST['key1']
        if key2 == '' or ciphertext == '':
            messages.warning(request, "Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
            ciphertext=remove(ciphertext)
            key2=int(key2)
            ciphertext=ciphertext.upper()

            result = decrypt(ciphertext, key2)
            key2=str(key2)
            context = {'CipherText': ciphertext, 'Key': key2, 'result': result}
            messages.success(request,'CipherText' + '=' + ciphertext + '      ' + 'Key' + '=' + key2 + '      ' + 'PlainText' + '=' + result)
            return render(request, 'attack/kshift.html', context)




            print(result)
    return render(request, 'attack/kshift.html')




# vignere cipher


def generateKey(string, key):
    key = list(key)
    if len(string) == len(key):
        return (key)
    else:
        for i in range(len(string) -
                       len(key)):
            key.append(key[i % len(key)])
    return ("".join(key))


# This function returns the
# encrypted text generated
# with the help of the key
def cipherText(string, key):
    cipher_text = []
    for i in range(len(string)):
        x = (ord(string[i]) +
             ord(key[i])) % 26
        x += ord('A')
        cipher_text.append(chr(x))
    return ("".join(cipher_text))


# This function decrypts the
# encrypted text and returns
# the original text
def originalText(cipher_text, key):
    orig_text = []
    for i in range(len(cipher_text)):
        x = (ord(cipher_text[i]) -
             ord(key[i]) + 26) % 26
        x += ord('A')
        orig_text.append(chr(x))
    return ("".join(orig_text))


def vignere(request):
    if request.method == 'POST' and 'enc' in request.POST:

        # get post parameters of encryption

        plaintext= request.POST['plaintext']
        plaintext=remove(plaintext)
        key1= request.POST['key']
        key1=remove(key1)
        if key1=='' or plaintext=='':
            messages.warning(request,"Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            plaintext=plaintext.upper()
            key1=key1.upper()
            key2=generateKey(plaintext,key1)


            # get post parameters for decryption
            result = cipherText(plaintext, key2)
            result=str(result)
            print(type(result))
            context={'plainText':plaintext,'Key':key1,'result':result}
            messages.success(request,'plainText'+'='+plaintext+'    '+'Key'+'='+key1+'    '+'CipherText'+'='+result)
            return render(request,'attack/vignere.html',context)
        #print(result)

    if request.method=='POST' and 'dec' in request.POST:
        ciphertext=request.POST['ciphertext']
        key2=request.POST['key1']
        ciphertext=remove(ciphertext)
        key2=remove(key2)
        if key2=='' or ciphertext=='':
            messages.warning(request,"Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            key2=key2.upper()
            ciphertext = ciphertext.upper()
            key1=generateKey(ciphertext,key2)

            result = originalText(ciphertext, key1)

            context = {'CipherText': ciphertext, 'Key': key2, 'result': result}
            messages.success(request,'CipherText' + '=' + ciphertext + '      ' + 'Key' + '=' + key2 + '      ' + 'PlainText' + '=' + result)
            return render(request, 'attack/vignere.html', context)





    return render(request, 'attack/vignere.html')


# vernam cipher

def generateKey(string, key):
    key = list(key)
    if len(string) == len(key):
        return (key)
    else:
        for i in range(len(string) -
                       len(key)):
            key.append(key[i % len(key)])
    return ("".join(key))


# This function returns the
# encrypted text generated
# with the help of the key
def cipherText(string, key):
    cipher_text = []
    for i in range(len(string)):
        x = (ord(string[i]) +
             ord(key[i])) % 26
        x += ord('A')
        cipher_text.append(chr(x))
    return ("".join(cipher_text))


# This function decrypts the
# encrypted text and returns
# the original text
def originalText(cipher_text, key):
    orig_text = []
    for i in range(len(cipher_text)):
        x = (ord(cipher_text[i]) -
             ord(key[i]) + 26) % 26
        x += ord('A')
        orig_text.append(chr(x))
    return ("".join(orig_text))

def vernam(request):
    if request.method == 'POST' and 'enc' in request.POST:

        # get post parameters of encryption

        plaintext= request.POST['plaintext']
        key1= request.POST['key']
        plaintext=remove(plaintext)
        key1=remove(key1)
        plaintext=plaintext.upper()
        key1=key1.upper()
        if key1=='' or plaintext=='':
            messages.warning(request,"Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            if len(plaintext)!=len(key1):
                messages.warning(request,"Hey Cryptogeek,There is an Error!!!!,Your key size is not same as plain text size")
            else:
                key2=generateKey(plaintext,key1)


            # get post parameters for decryption
                result = cipherText(plaintext, key2)
                result=str(result)
                print(type(result))
                context={'plainText':plaintext,'Key':key1,'result':result}
                messages.success(request,'plainText'+'='+plaintext+'    '+'Key'+'='+key1+'    '+'CipherText'+'='+result)
                return render(request,'attack/vernam.html',context)


    if request.method=='POST' and 'dec' in request.POST:
        ciphertext=request.POST['ciphertext']
        key2=request.POST['key1']
        ciphertext=remove(ciphertext)
        key2=remove(key2)
        key2=key2.upper()
        ciphertext = ciphertext.upper()
        if key2=='' or ciphertext=='':
            messages.warning(request, "Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            if len(ciphertext) != len(key2):
                messages.warning(request,"Hey Cryptogeek,There is an Error!!!!,Your key size is not same as plain text size")
            else:
                key1=generateKey(ciphertext,key2)

                result = originalText(ciphertext, key1)

                context = {'CipherText': ciphertext, 'Key': key2, 'result': result}
                messages.success(request,'CipherText' + '=' + ciphertext + '      ' + 'Key' + '=' + key2 + '      ' + 'PlainText' + '=' + result)
                return render(request, 'attack/vernam.html', context)





    return render(request, 'attack/vernam.html')


# Rail fence cipher

# Python3 program to illustrate
# Rail Fence Cipher Encryption
# and Decryption

# function to encrypt a message
def encryptRailFence(text, key):
    # create the matrix to cipher
    # plain text key = rows ,
    # length(text) = columns
    # filling the rail matrix
    # to distinguish filled
    # spaces from blank ones
    rail = [['\n' for i in range(len(text))]
            for j in range(key)]

    # to find the direction
    dir_down = False
    row, col = 0, 0

    for i in range(len(text)):

        # check the direction of flow
        # reverse the direction if we've just
        # filled the top or bottom rail
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down

        # fill the corresponding alphabet
        rail[row][col] = text[i]
        col += 1

        # find the next row using
        # direction flag
        if dir_down:
            row += 1
        else:
            row -= 1
    # now we can construct the cipher
    # using the rail matrix
    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return ("".join(result))


# This function receives cipher-text
# and key and returns the original
# text after decryption
def decryptRailFence(cipher, key):
    # create the matrix to cipher
    # plain text key = rows ,
    # length(text) = columns
    # filling the rail matrix to
    # distinguish filled spaces
    # from blank ones
    rail = [['\n' for i in range(len(cipher))]
            for j in range(key)]

    # to find the direction
    dir_down = None
    row, col = 0, 0

    # mark the places with '*'
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False

        # place the marker
        rail[row][col] = '*'
        col += 1

        # find the next row
        # using direction flag
        if dir_down:
            row += 1
        else:
            row -= 1

    # now we can construct the
    # fill the rail matrix
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if ((rail[i][j] == '*') and
                    (index < len(cipher))):
                rail[i][j] = cipher[index]
                index += 1

    # now read the matrix in
    # zig-zag manner to construct
    # the resultant text
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):

        # check the direction of flow
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False

        # place the marker
        if (rail[row][col] != '*'):
            result.append(rail[row][col])
            col += 1

        # find the next row using
        # direction flag
        if dir_down:
            row += 1
        else:
            row -= 1
    return ("".join(result))



def railfence(request):
    if request.method == 'POST' and 'enc' in request.POST:

        # get post parameters of encryption

        plaintext= request.POST['plaintext']
        key1= request.POST['key']

        if key1=='' or plaintext=='':
            messages.warning(request,"Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            plaintext=plaintext.upper()

            key1 = int(key1)

            # get post parameters for decryption
            result = encryptRailFence(plaintext, key1)
            context={'plainText':plaintext,'Key':key1,'result':result}
            key1=str(key1)
            messages.success(request,'plainText'+'='+plaintext+'    '+'Key'+'='+key1+'    '+'CipherText'+'='+result)
            return render(request,'attack/railfence.html',context)
        #print(result)

    if request.method=='POST' and 'dec' in request.POST:
        ciphertext=request.POST['ciphertext']
        key2=request.POST['key1']

        if key2=='' or ciphertext=='':
            messages.warning(request,"Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            key2=int(key2)
            ciphertext=ciphertext.upper()

            result =decryptRailFence(ciphertext, key2)
            key2=str(key2)
            context = {'CipherText': ciphertext, 'Key': key2, 'result': result}
            messages.success(request,'CipherText' + '=' + ciphertext + '      ' + 'Key' + '=' + key2 + '      ' + 'PlainText' + '=' + result)
            return render(request, 'attack/railfence.html', context)




    return render(request, 'attack/railfence.html')


#playfair





def matrix(x, y, initial):
    return [[initial for i in range(x)] for j in range(y)]

def locindex(c,my_matrix):  # get location of each character
    loc = list()
    if c == 'J':
        c = 'I'
    for i, j in enumerate(my_matrix):
        for k, l in enumerate(j):
            if c == l:
                loc.append(i)
                loc.append(k)
                return loc


def encrypt_playfair(msg,my_matrix):  # Encryption

    msg = msg.upper()
    msg = msg.replace(" ", "")
    i = 0
    st=''
    for s in range(0, len(msg) + 1, 2):
        if s < len(msg) - 1:
            if msg[s] == msg[s + 1]:
                msg = msg[:s + 1] + 'X' + msg[s + 1:]
    if len(msg) % 2 != 0:
        msg = msg[:] + 'X'

    while i < len(msg):
        loc = list()
        loc = locindex(msg[i],my_matrix)
        loc1 = list()
        loc1 = locindex(msg[i + 1],my_matrix)
        if loc[1] == loc1[1]:
            #print("{}{}".format(my_matrix[(loc[0] + 1) % 5][loc[1]], my_matrix[(loc1[0] + 1) % 5][loc1[1]]), end=' ')
            st=st+my_matrix[(loc[0] + 1) % 5][loc[1]]+my_matrix[(loc1[0] + 1) % 5][loc1[1]]
        elif loc[0] == loc1[0]:
            #print("{}{}".format(my_matrix[loc[0]][(loc[1] + 1) % 5], my_matrix[loc1[0]][(loc1[1] + 1) % 5]), end=' ')
            st=st+my_matrix[loc[0]][(loc[1] + 1) % 5]+ my_matrix[loc1[0]][(loc1[1] + 1) % 5]
        else:
            #print("{}{}".format(my_matrix[loc[0]][loc1[1]], my_matrix[loc1[0]][loc[1]]), end=' ')
            st=st+my_matrix[loc[0]][loc1[1]]+my_matrix[loc1[0]][loc[1]]
        i = i + 2
    return st


def decrypt_playfair(msg,my_matrix):  # decryption
    st=''
    msg = msg.upper()
    msg = msg.replace(" ", "")

    i = 0
    while i < len(msg):
        loc = list()
        loc = locindex(msg[i],my_matrix)
        loc1 = list()
        loc1 = locindex(msg[i + 1],my_matrix)
        if loc[1] == loc1[1]:
            #print("{}{}".format(my_matrix[(loc[0] - 1) % 5][loc[1]], my_matrix[(loc1[0] - 1) % 5][loc1[1]]), end=' ')
            st=st+my_matrix[(loc[0] - 1) % 5][loc[1]]+my_matrix[(loc1[0] - 1) % 5][loc1[1]]
        elif loc[0] == loc1[0]:
            #print("{}{}".format(my_matrix[loc[0]][(loc[1] - 1) % 5], my_matrix[loc1[0]][(loc1[1] - 1) % 5]), end=' ')
            st=st+my_matrix[loc[0]][(loc[1] - 1) % 5]+ my_matrix[loc1[0]][(loc1[1] - 1) % 5]
        else:
            #print("{}{}".format(my_matrix[loc[0]][loc1[1]], my_matrix[loc1[0]][loc[1]]), end=' ')
            st=st+my_matrix[loc[0]][loc1[1]]+ my_matrix[loc1[0]][loc[1]]
        i = i + 2
    return st


def playfair(request):
    if request.method == 'POST' and 'enc' in request.POST:

        # get post parameters of encryption

        plaintext = request.POST['plaintext']
        plaintext = remove(plaintext)
        key1 = request.POST['key']
        key1 = remove(key1)

        if key1 == '' or plaintext == '':
            messages.warning(request, "Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            plaintext = plaintext.upper()

            key1 = key1.replace(" ", "")
            key1 = key1.upper()
            key=key1
            msg=plaintext
            #################

            result = list()
            for c in key:  # storing key
                if c not in result:
                    if c == 'J':
                        result.append('I')
                    else:
                        result.append(c)
            flag = 0
            for i in range(65, 91):  # storing other character
                if chr(i) not in result:
                    if i == 73 and chr(74) not in result:
                        result.append("I")
                        flag = 1
                    elif flag == 0 and i == 73 or i == 74:
                        pass
                    else:
                        result.append(chr(i))
            k = 0
            my_matrix = matrix(5, 5, 0)  # initialize matrix
            for i in range(0, 5):  # making matrix
                for j in range(0, 5):
                    my_matrix[i][j] = result[k]
                    k += 1



            ###############


            # get post parameters for decryption
            result1=encrypt_playfair(msg,my_matrix)
            result1 = str(result1)
            #result1=None
            context = {'plainText': plaintext, 'Key': key1, 'result': result1}
            messages.success(request, 'plainText' + '=' + plaintext + '    ' + 'Key' + '=' + key1 + '    ' + 'CipherText' + '=' + result1)
            return render(request, 'attack/playfair.html')
        # print(result)

    if request.method == 'POST' and 'dec' in request.POST:
        ciphertext = request.POST['ciphertext']
        key2 = request.POST['key1']
        ciphertext = remove(ciphertext)
        key2 = remove(key2)
        if key2 == '' or ciphertext == '':
            messages.warning(request, "Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            key2= key2.replace(" ", "")
            key2= key2.upper()
            ciphertext = ciphertext.upper()
            key=key2

            ##########################
            result = list()
            for c in key:  # storing key
                if c not in result:
                    if c == 'J':
                        result.append('I')
                    else:
                        result.append(c)
            flag = 0
            for i in range(65, 91):  # storing other character
                if chr(i) not in result:
                    if i == 73 and chr(74) not in result:
                        result.append("I")
                        flag = 1
                    elif flag == 0 and i == 73 or i == 74:
                        pass
                    else:
                        result.append(chr(i))
            k = 0
            my_matrix = matrix(5, 5, 0)  # initialize matrix
            for i in range(0, 5):  # making matrix
                for j in range(0, 5):
                    my_matrix[i][j] = result[k]
                    k += 1

            #####################


            result2=decrypt_playfair(ciphertext,my_matrix)

            context = {'CipherText': ciphertext, 'Key': key2, 'result': result2}
            messages.success(request,
                             'CipherText' + '=' + ciphertext + '      ' + 'Key' + '=' + key2 + '      ' + 'PlainText' + '=' + result2)
            return render(request, 'attack/playfair.html', context)

    return render(request, 'attack/playfair.html')

# columnar transposition

import math




# Encryption
def encryptMessage(msg,key):
    cipher = ""

    # track key indices
    k_indx = 0

    msg_len = float(len(msg))
    msg_lst = list(msg)
    key_lst = sorted(list(key))
    # print(key_lst)
    # calculate column of the matrix
    col = len(key)

    # calculate maximum row of the matrix
    row = int(math.ceil(msg_len / col))

    # add the padding character '_' in empty
    # the empty cell of the matix
    fill_null = int((row * col) - msg_len)
    msg_lst.extend('_' * fill_null)

    # create Matrix and insert message and
    # padding characters row-wise
    matrix = [msg_lst[i: i + col]
              for i in range(0, len(msg_lst), col)]

    # read matrix column-wise using key
    for _ in range(col):
        curr_idx = key.index(key_lst[k_indx])
        cipher += ''.join([row[curr_idx]
                           for row in matrix])
        k_indx += 1

    return cipher


# Decryption
def decryptMessage(msg, key):
	'''
	Deciphers message using key.
		- decrypted message may be suffixed by meaningless characters
	'''
	# calculate the order we need to apply to it, sorted by ASCII acrrodingly
	order = [key.find(x) for x in sorted(key)]
	# analyze the string so that we can reverse the result to x in encryption
	chunks = [msg[k+x*int(len(msg)/len(key))] for k in range(int(len(msg)/len(key))) for x in range(len(key))]

	# removing all the symbols
	chunks = ''.join(chunks)

	# retrive how each row was picked
	chunks = [chunks[i:i+len(key)] for i in range(0, len(chunks), len(key))]

	x = map(lambda k: ''.join([c for (y,c) in sorted(zip(order, k))]), chunks)
	return ''.join(x)



def columnar(request):
    if request.method == 'POST' and 'enc' in request.POST:

        # get post parameters of encryption

        plaintext= request.POST['plaintext']
        #plaintext=remove(plaintext)
        key1= request.POST['key']
        key1=remove(key1)
        if key1=='' or plaintext=='':
            messages.warning(request,"Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            plaintext=plaintext.upper()
            key1=key1.upper()



            # get post parameters for decryption
            result = encryptMessage(plaintext, key1)
            result=str(result)
            print(type(result))
            context={'plainText':plaintext,'Key':key1,'result':result}
            messages.success(request,'plainText'+'='+plaintext+'    '+'Key'+'='+key1+'    '+'CipherText'+'='+result)
            return render(request,'attack/columnar.html',context)
        #print(result)

    if request.method=='POST' and 'dec' in request.POST:
        ciphertext=request.POST['ciphertext']
        key2=request.POST['key1']

        key2=remove(key2)
        if key2=='' or ciphertext=='':
            messages.warning(request,"Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            key2=key2.upper()
            ciphertext = ciphertext.upper()


            result =decryptMessage(ciphertext, key2)

            context = {'CipherText': ciphertext, 'Key': key2, 'result': result}
            messages.success(request,'CipherText' + '=' + ciphertext + '      ' + 'Key' + '=' + key2 + '      ' + 'PlainText' + '=' + result)
            return render(request, 'attack/columnar.html', context)





    return render(request, 'attack/columnar.html')


# hill cipher
import numpy as np
import math


def getKeyMatrix(key):
  np.keyMatrix = [[0] * 3 for i in range(3)]
  k = 0
  for i in range(3):
    for j in range(3):
      np.keyMatrix[i][j] = ord(key[k]) % 65
      k += 1

def encrypt_hill(messageVector,cipherMatrix):
  for i in range(3):
    for j in range(1):
      cipherMatrix[i][j] = 0
      for x in range(3):
        cipherMatrix[i][j] += (np.keyMatrix[i][x] * messageVector[x][j])
        cipherMatrix[i][j] = cipherMatrix[i][j] % 26

def HillCipher1(message, key,cipherMatrix,messageVector):
  getKeyMatrix(key)
  for i in range(3):
    messageVector[i][0] = ord(message[i]) % 65
  encrypt_hill(messageVector,cipherMatrix)
  CipherText = []
  for i in range(3):
    CipherText.append(chr(cipherMatrix[i][0] + 65))
  return "".join(CipherText)

def getInverseKeyMatrix(key):
  getKeyMatrix(key)
  keyMatrix=np.keyMatrix
  from sympy import Matrix
  try:
    inverseKeyMatrix = Matrix(keyMatrix).inv_mod(26)
    np.inverseKeyMatrix = np.array(inverseKeyMatrix)
  except Exception as e:
      print(e)



def getty_inv(key):
    getKeyMatrix(key)
    keyMatrix = np.keyMatrix
    from sympy import Matrix
    try:
        inverseKeyMatrix = Matrix(keyMatrix).inv_mod(26)
        np.inverseKeyMatrix = np.array(inverseKeyMatrix)
        inv = inverseKeyMatrix
        return inv
    except Exception as e:
        print(e)


def HillCipher2(message, key,plainMatrix,messageVector):
  getInverseKeyMatrix(key)
  for i in range(3):
    messageVector[i][0] = ord(message[i]) % 65
  decrypt_hill(plainMatrix,messageVector)
  PlainText = []
  for i in range(3):
    PlainText.append(chr(int(round(plainMatrix[i][0]) + 65)))
  return "".join(PlainText)

def decrypt_hill(plainMatrix,messageVector):
  for i in range(3):
    for j in range(1):
      plainMatrix[i][j] = 0
      for x in range(3):
        plainMatrix[i][j] = plainMatrix[i][j] % 26
        plainMatrix[i][j] += (np.inverseKeyMatrix[i][x] * messageVector[x][j])
      plainMatrix[i][j] = plainMatrix[i][j] % 26



from sympy import lambdify
from sympy.abc import x, y





def hill(request):
    if request.method == 'POST' and 'enc' in request.POST:

        # get post parameters of encryption

        plaintext = request.POST['plaintext']
        key1 = request.POST['key']
        plaintext = remove(plaintext)
        key1 = remove(key1)
        plaintext = plaintext.upper()
        key1 = key1.upper()
        if key1 == '' or plaintext == '':
            messages.warning(request, "Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            if len(plaintext) > 3:
                messages.warning(request,
                                 "Hey Cryptogeek,There is an Error!!!!,Your key size is not same as plain text size")
            else:

                ############################################


                messageVector = [[0] for i in range(3)]
                cipherMatrix = [[0] for i in range(3)]
                plainMatrix = [[0] for i in range(3)]
                np.inverseKeyMatrix = [[0] * 3 for i in range(3)]

                ############################################

                # get post parameters for decryption
                result = HillCipher1(plaintext, key1,cipherMatrix,messageVector)
                result = str(result)

                context = {'plainText': plaintext, 'Key': key1, 'result': result}
                messages.success(request,
                                 'plainText' + '=' + plaintext + '    ' + 'Key' + '=' + key1 + '    ' + 'CipherText' + '=' + result)
                return render(request, 'attack/hill.html', context)

    if request.method == 'POST' and 'dec' in request.POST:
        ciphertext = request.POST['ciphertext']
        key2 = request.POST['key1']
        ciphertext = remove(ciphertext)
        key2 = remove(key2)
        key2 = key2.upper()
        ciphertext = ciphertext.upper()
        if key2 == '' or ciphertext == '':
            messages.warning(request, "Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            if len(ciphertext) > 3:
                messages.warning(request,
                                 "Hey Cryptogeek,There is an Error!!!!,Your key size is not same as plain text size")
            else:
                ###########################

                messageVector = [[0] for i in range(3)]
                cipherMatrix = [[0] for i in range(3)]
                plainMatrix = [[0] for i in range(3)]
                np.inverseKeyMatrix = [[0] * 3 for i in range(3)]

                ############################################
                inverse=getty_inv(key2)
                g=inverse
                invy = " "
                if g!=None:
                    s = (x, y)
                    g_func = lambdify(s, g, modules='numpy')
                    aa=g_func(1,1)
                    aa=aa.tolist()
                    invy=" "
                    for i in aa:
                        p=str(i)
                        invy=invy+p
                elif g==None:
                    messages.success(request,"Matrix is not invertible (mod 26)")
                    return render(request,'attack/hill.html')

                #print(type(invy))
                #print(invy)

                result =HillCipher2(ciphertext, key2,plainMatrix,messageVector)

                context = {'CipherText': ciphertext, 'Key': key2, 'result': result}
                messages.success(request,
                                 'CipherText' + '=' + ciphertext + '      ' + 'Key' + '=' + key2 + '      ' + 'PlainText' + '=' + result+'\n'+'Inverse Matrix'+'='+invy)
                return render(request, 'attack/hill.html', context)

    return render(request, 'attack/hill.html')


# sdes


p8_table = [6, 3, 7, 4, 8, 5, 10, 9]
p10_table = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
p4_table = [2, 4, 3, 1]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
expansion = [4, 1, 2, 3, 2, 3, 4, 1]
s0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
s1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]


def apply_table(inp, table):
    """
    >>> apply_table("0123456789", list(range(10)))
    '9012345678'
    >>> apply_table("0123456789", list(range(9, -1, -1)))
    '8765432109'
    """
    res = ""
    for i in table:
        res += inp[i - 1]
    return res


def left_shift(data):
    """
    >>> left_shift("0123456789")
    '1234567890'
    """
    return data[1:] + data[0]


def XOR(a, b):
    """
    >>> XOR("01010101", "00001111")
    '01011010'
    """
    res = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            res += "0"
        else:
            res += "1"
    return res


def apply_sbox(s, data):
    row = int("0b" + data[0] + data[-1], 2)
    col = int("0b" + data[1:3], 2)
    return bin(s[row][col])[2:]


def function(expansion, s0, s1, key, message):
    left = message[:4]
    right = message[4:]
    temp = apply_table(right, expansion)
    temp = XOR(temp, key)
    l = apply_sbox(s0, temp[:4])  # noqa: E741
    r = apply_sbox(s1, temp[4:])
    l = "0" * (2 - len(l)) + l  # noqa: E741
    r = "0" * (2 - len(r)) + r
    temp = apply_table(l + r, p4_table)
    temp = XOR(left, temp)
    return temp + right



    # key generation
def key_sdes(key):
    list_key=[]
    temp = apply_table(key, p10_table)
    left = temp[:5]
    right = temp[5:]
    left = left_shift(left)
    right = left_shift(right)
    key1 = apply_table(left + right, p8_table)
    left = left_shift(left)
    right = left_shift(right)
    left = left_shift(left)
    right = left_shift(right)
    key2 = apply_table(left + right, p8_table)
    list_key.append(key1)
    list_key.append(key2)
    return list_key

    # encryption
def en_sdes(message,key1,key2):
    temp = apply_table(message, IP)
    temp = function(expansion, s0, s1, key1, temp)
    temp = temp[4:] + temp[:4]
    temp = function(expansion, s0, s1, key2, temp)
    CT = apply_table(temp, IP_inv)
    #print("Cipher text is:", CT)
    return CT

    # decryption
def de_sdes(CT,key1,key2):
    temp = apply_table(CT, IP)
    temp = function(expansion, s0, s1, key2, temp)
    temp = temp[4:] + temp[:4]
    temp = function(expansion, s0, s1, key1, temp)
    PT = apply_table(temp, IP_inv)
    #print("Plain text after decypting is:", PT)
    return PT

def sdes(request):
    if request.method == 'POST' and 'enc' in request.POST:

        # get post parameters of encryption

        plaintext= request.POST['plaintext']
        key= request.POST['key']
        plaintext=remove(plaintext)
        key=remove(key)

        if key=='' or plaintext=='':
            messages.warning(request,"Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            if len(plaintext)!=8 or len(key)!=10:
                messages.warning(request,"Hey Cryptogeek,There is an Error!!!!,Your key size must be 10 and message size must be 8")
            else:
                key2=key_sdes(key)


            # get post parameters for decryption
                result =en_sdes(plaintext, key2[0],key2[1])
                result=str(result)
                print(type(result))
                context={'plainText':plaintext,'Key1':key2[0],'result':result}
                messages.success(request,'plainText'+'='+plaintext+'    '+'Key'+'='+key+'    '+'CipherText'+'='+result+'     '+'Subkey_1'+'='+key2[0]+'    '+'Subkey_2'+'='+key2[1])
                return render(request,'attack/sdes.html',context)


    if request.method=='POST' and 'dec' in request.POST:
        ciphertext=request.POST['ciphertext']
        key=request.POST['key1']
        ciphertext=remove(ciphertext)
        key=remove(key)

        if key=='' or ciphertext=='':
            messages.warning(request, "Hey Cryptogeek, Invalid input from your side !!!!, Please provide valid input ")
        else:
            if len(ciphertext) !=8 or len(key)!=10:
                messages.warning(request,"Hey Cryptogeek,There is an Error!!!!,Your key size must be equals to 10 and cipher text must be 8")
            else:
                key1=key_sdes(key)

                result =de_sdes(ciphertext, key1[0],key1[1])

                context = {'CipherText': ciphertext, 'Key': key1[0], 'result': result}
                messages.success(request,'CipherText' + '=' + ciphertext + '      ' + 'Key' + '=' + key + '      ' + 'PlainText' + '=' + result+'     '+'Subkey_1'+'='+key1[0]+'    '+'Subkey_2'+'='+key1[1])
                return render(request, 'attack/sdes.html', context)





    return render(request, 'attack/sdes.html')


def contact_cipher(request):
    if request.method=='POST' and 'sent' in request.POST:
        name=request.POST['name']
        email=request.POST['email']
        subject=request.POST['subject']
        message=request.POST['message']
        print(name)
        ask=contact(name=name,email=email,subject=subject,message=message)
        ask.save()
       # send_mail('CIPHERX', 'Thank You for your valuable Feedback! we will reach to you soon'
        #          , settings.EMAIL_HOST_USER,
         #         [email], fail_silently=False
          #        )
        return redirect('home')