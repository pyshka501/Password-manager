import random

# int(input("length_salt: "))
salt_lcla = []
coeff_shift = 60000
cipher_text = list(input("Text: "))


# } - max ord


def gen_salt(cipher_text):
    length_salt = len(cipher_text)
    for i in range(length_salt):
        salt_lcla.append(random.randint(2 ** 2, 2 ** 10))
    print(salt_lcla)
    return salt_lcla


salt_lcla = [83, 171, 273, 377, 406, 524, 308, 125, 473, 996, 282, 631]


def cipher(cipher_text, salt_lcla):
    bias_salt = len(cipher_text)
    for i in range(len(cipher_text)):
        cipher_text[i] = (chr(coeff_shift + abs(((ord(cipher_text[i]) - salt_lcla[i]) * bias_salt))))

    cihper_string = bytes(chr(salt_lcla[0]).join(cipher_text), encoding="UTF-8")
    print(cihper_string)
    return [cihper_string, salt_lcla]


a = cipher(cipher_text, salt_lcla) 


def decipher(cihper_string_b, salt_lcla):
    pass

    cihper_string = cihper_string_b.decode('utf-8')
    cihper_list = cihper_string.split(chr(salt_lcla[0]))
    for i in range(len(cihper_list)):
        cihper_list[i] = chr(abs(((ord(cihper_list[i]) - coeff_shift) // len(cihper_list)) - salt_lcla[i]))
    cipher_text = "".join(cihper_list)
    print(cipher_text)
    return cipher_text    
    
   decipher(a[0], a[1])
