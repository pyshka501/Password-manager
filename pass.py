import hashlib
import random
from tkinter import *
from tkinter import messagebox
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import sqlite3 as sq



colour_for_yes_no = "#dedede"  # dbdbdb
main_colour = "#d4d4d4"  # e0e0e0
font_for_all = "Arial 15"  #
colour_for_entry = "#c9c9c9"  # c9c9c9
colour_for_back = "#dedede"  # bebfc2
place_w = "+660+440"

salt_for_log_in = b'\x0e!\xa8\xaa\x8a\xc7C\xb6*\xff\xef\tTL\xbf8\x85\x01\x12\x99\x04\xac\xc9\t\xfaVXU\xcc#%M'

symbols = 'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm123456790()[]@{}*#_-+'

number = 24

num = len(symbols) - 1

key_enc = 'adksfjndfasln'

dict_f = {}

row_id = 0

# creating files

with sq.connect("saper_log.db") as con:
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users_pass (

        cipher_text TEXT,
        salt TEXT,
        nonce TEXT,
        tag TEXT
        )""")

with sq.connect("saper_log.db") as con:
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users_reg (

        cipher_text TEXT,
        salt TEXT,
        nonce TEXT,
        tag TEXT
        )""")

with open('test.txt', 'w') as f:
    f.write('')
with open('regis.txt', 'w') as f:
    f.write('')


# crypto

def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    row_id = 0

    with sq.connect("saper_log.db") as con:
        cur = con.cursor()
        cur.execute("SELECT max(rowid) FROM users_pass")
        fl = cur.fetchall()
    if fl != [(None,)]:
        row_id = fl[0][0] + 1



    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        'row_id' : row_id
    }


def decrypt(enc_dict, key_enc):
    row_id = 0
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    if 'row_id' in enc_dict:
        row_id = enc_dict['row_id']


    # generate the private key from the password and salt
    private_key = hashlib.scrypt(key_enc.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    bdecrypted = cipher.decrypt_and_verify(cipher_text, tag)
    decrypted = bytes.decode(bdecrypted)

    return decrypted


def wr_in_db(web, log, pas):
    with sq.connect("saper_log.db") as con:
        cur = con.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users_pass (

            cipher_text TEXT,
            salt TEXT,
            nonce TEXT,
            tag TEXT
            )""")
        x = encrypt(f"Name of website: {web}, login: {log}, password: {pas}", key_enc)

        cur = con.cursor()
        cur.execute("SELECT max(rowid) FROM users_pass")
        fl = cur.fetchall()
        if fl != [(None,)]:
            row_id = fl[0][0] + 1

        else:
            row_id = 0

        r = f"INSERT INTO users_pass VALUES('{x['cipher_text']}', '{x['salt']}', '{x['nonce']}', '{x['tag']}')"
        cur.execute(r)


# work with db

def taking_data():
    with sq.connect("saper_log.db") as con:
        cur = con.cursor()
        cur.execute("SELECT * FROM users_pass")
        fl = cur.fetchall()

        def making_dict():
            for i in range(len(fl)):
                enc_dict = {'cipher_text': fl[i][0], 'salt': fl[i][1], 'nonce': fl[i][2], 'tag': fl[i][3]}
                decrypted = decrypt(enc_dict, key_enc)
                cur.execute(f"SELECT rowid FROM users_pass WHERE cipher_text = '{fl[i][0]}' ")
                enc_dict['row_id'] = cur.fetchall()


                with open('test.txt', 'a+') as f:  # записываем в файл уже дешифр
                    finished_line = decrypted + '\n'

                    f.write(finished_line)

        making_dict()


def taking_data_reg():
    with sq.connect("saper_log.db") as con:
        cur = con.cursor()
        cur.execute("SELECT * FROM users_reg")
        fl = cur.fetchall()

        def making_dict():
            for i in range(len(fl)):
                enc_dict = {'cipher_text': fl[i][0], 'salt': fl[i][1], 'nonce': fl[i][2], 'tag': fl[i][3]}
                decrypted = decrypt(enc_dict, key_enc)

                with open('regis.txt', 'a+') as f:  # записываем в файл уже дешифр

                    finished_line = decrypted + '\n'
                    f.write(finished_line)

        making_dict()


# main func


def clear():
    a = root_acc.grid_slaves()  # очищаем предыдущее окно
    for i in a:
        i.destroy()
    location()


def save_reg(log, pas):  # сохраняем пароль и логин в базу
    logg = log
    pasg = pas
    with open('test.txt', "w") as f:
        f.write('')
    clear()  # очищение

    if " " in str(logg):
        messagebox.showinfo("!!!", """You can not use 'space'!!!""")
        registration(root_acc)
    elif " " in str(pasg):
        messagebox.showinfo("!!!", """You can not use 'space'!!!""")
        registration(root_acc)
    else:
        string_pas = str(logg) + str(pasg)

        string_en = encrypt(string_pas, key_enc)

        with sq.connect("saper_log.db") as con:
            cur = con.cursor()
            cur.execute("DELETE FROM users_reg")
            cur.execute("""CREATE TABLE IF NOT EXISTS users_reg (
                cipher_text TEXT,
                salt TEXT,
                nonce TEXT,
                tag TEXT
                )""")
            cur.execute(
                f"INSERT INTO users_reg VALUES('{string_en['cipher_text']}','{string_en['salt']}','{string_en['nonce']}','{string_en['tag']}')")
        taking_data_reg()
        messagebox.showinfo("","You have been registered")
        first_choice()


# Работа с паролями
def generation_pass():
    clear()  # очищение

    Label(font=font_for_all, text="Enter length of your needed password(max 15).", bg=main_colour, height=2).grid(row=0,
                                                                                                                  column=0,
                                                                                                                  columnspan=2,
                                                                                                                  sticky='wens')
    bt_ge = Button(font=font_for_all, text="Generate password", command=lambda: final_gener(length_p),
                   bg=colour_for_back)
    bt_ge.grid(row=1, column=0, sticky='wens')
    length_p = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
    length_p.grid(row=1, column=1, sticky='wens')
    bac = Button(font=font_for_all, text='Back', command=lambda: first_choice(), bg=colour_for_back)
    bac.grid(row=2, column=0, sticky='wens')

    def final_gener(length):

        password = []

        l = length.get()

        clear()  # очищение

        # function

        def gener(l):
            if int(l) > 15:
                l = 15
            for i in range(int(l)):
                key = random.randint(0, num)
                password.append(symbols[key])
            p = "".join(password)
            text = Label(font=font_for_all, text=p, bg=main_colour)
            text.grid(row=0, column=0, sticky='wens')
            text = Listbox(height=1, font=font_for_all, bg=colour_for_yes_no)
            text.insert(1, p)
            text.grid(row=0, column=0, sticky='wens')

            Label(font=font_for_all, text=' - your generated password', bg=main_colour, height=1).grid(row=0, column=1,
                                                                                             sticky='wens')

        try:
            gener(l)
            Button(font=font_for_all, text='Back', command=lambda: first_choice(), bg=colour_for_back).grid(row=1,
                                                                                                            column=0,
                                                                                                            sticky='wens')

        except:
            messagebox.showinfo("!!!", """You can not use symbols or letters or nothing!!!""")
            generation_pass()


def wp():
    clear()

    # y = bt_chp.winfo_height()   width=26

    Label(font=font_for_all, text="Choose action: print list of passwords, add passwords and clear list up.",
          bg=main_colour, height=2).grid(
        row=0, column=0, columnspan=2, sticky='wens')
    bt_ap = Button(font=font_for_all, bg=colour_for_back, text="Add password", width=26, command=lambda: add_password())
    bt_ap.grid(row=1, column=0, sticky='wens')
    bt_pp = Button(font=font_for_all, bg=colour_for_back, text="Print passwords", width=26, command=lambda: print_password())
    bt_pp.grid(row=3, column=0, sticky='wens')
    bt_cp = Button(font=font_for_all, bg=colour_for_back, text="Clear list of passwords", width=26, command=lambda: clear_password())
    bt_cp.grid(row=1, column=1, sticky='wens')
    bt_chp = Button(font=font_for_all, bg=colour_for_back, text="Change one of the passwords", width=26, command=lambda: change_pass())
    bt_chp.grid(row=2, column=0, sticky='wens')
    bt_dop = Button(font=font_for_all, bg=colour_for_back, text="Delete one of the passwords", width=26, command=lambda: delete_one_pass())
    bt_dop.grid(row=2, column=1, sticky='wens')

    bt_back = Button(font=font_for_all, bg=colour_for_back ,text="Back", width=26, command=lambda: first_choice())
    bt_back.grid(row=3, column=1, sticky='wens')

    def change_pass():
        clear()

        Label(font=font_for_all, text="What password do you want to change?", bg=main_colour, height=2).grid(
            columnspan=2)
        Label(font=font_for_all, text="Name of website:", bg=main_colour).grid(row=1, sticky='wens')
        c_site = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
        c_site.grid(row=1, column=1, sticky='wens')

        bt_back = Button(font=font_for_all, text="Enter", width=23, command=lambda: getting_d_pass(),
                         bg=colour_for_back)
        bt_back.grid(row=2, column=1, sticky='wens')
        bt_back = Button(font=font_for_all, text="Back", width=23, command=lambda: wp(), bg=colour_for_back)
        bt_back.grid(row=2, column=0, sticky='wens')

        def getting_d_pass():
            cs = c_site.get()
            counter_log = []
            counter_site = []

            if cs == "":
                messagebox.showerror("!!!", "Fill in the field")
                delete_one_pass()

            elif cs != "":
                delete_site = cs
                taking_data()
                with open('test.txt') as f:
                    lines = f.readlines()
                with open('test.txt', "w") as f:
                    f.write('')
                lines_s = []
                con_site = 0
                for i in range(len(lines)):
                    try:
                        s_i = lines[i].index(',')
                        lines_s.append(lines[i][:s_i].split())
                        if delete_site in lines_s[i]:
                            con_site = 1
                            counter_site.append(i)
                    except ValueError:
                        messagebox.showerror('!!!', 'There is not at least one password!')
                        clear()
                        Label(font=font_for_all, text="Do You want to add password?", bg=main_colour, height=2).grid(row=0,
                                                                                                           column=0,
                                                                                                           columnspan=2,
                                                                                                           sticky='wens')
                        Button(font=font_for_all, text="Yes", command=lambda: add_password()).grid(row=1, column=1,
                                                                                                   sticky='wens',
                                                                                                   bg=colour_for_yes_no)
                        Button(font=font_for_all, text="No", command=lambda: wp()).grid(row=1, column=0, sticky='wens',
                                                                                        bg=colour_for_yes_no)

                if lines == [] or 'Name' not in lines_s[0]:
                    clear()
                    with open('test.txt', "w") as f:
                        f.write('')
                    messagebox.showinfo("", "There is not at least one password.")
                    Label(font=font_for_all, text="Do You want to add password?", bg=main_colour, height=2).grid(row=0, column=0,
                                                                                                       columnspan=2,
                                                                                                       sticky='wens')
                    Button(font=font_for_all, text="Yes", command=lambda: add_password(), bg=colour_for_yes_no).grid(
                        row=1,
                        column=1,
                        sticky='wens')
                    Button(font=font_for_all, text="No", command=lambda: wp(), bg=colour_for_yes_no).grid(row=1, column=0, sticky='wens')
                elif lines != [] and con_site == 1:
                    clear()
                    Label(font=font_for_all, text="Enter login of this password", bg=main_colour).grid(
                        columnspan=3,
                        sticky='wens')
                    Label(font=font_for_all, text="Login:", bg=main_colour).grid(row=1, column=1, sticky='wens')
                    d_login = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
                    d_login.grid(row=1, column=2, sticky='wens')

                    bt_ent = Button(font=font_for_all, bg=colour_for_back, text="Enter", width=23, command=lambda: d_log_final())
                    bt_ent.grid(row=2, column=2, sticky='wens')
                    bt_back = Button(font=font_for_all, text="Back", width=23, command=lambda: change_pass(),
                                     bg=colour_for_back)
                    bt_back.grid(row=2, column=1, sticky='wens')

                    def d_log_final():

                        log_for_delet = d_login.get()
                        if log_for_delet == "":
                            messagebox.showerror("!!!", "Fill in the field")
                            getting_d_pass()
                        taking_data()
                        with open('test.txt') as f:
                            lines = f.readlines()
                        with open('test.txt', "w") as f:
                            f.write('')
                        lines_l = []
                        con_log = 0
                        for i in range(len(lines)):
                            log_in_line = str(lines[i]).split(',')
                            lines_l.append(log_in_line[1])
                            login_only = str(lines_l[i]).split(" ")

                            if str(log_for_delet) == str(login_only[2]):
                                con_log = 1
                                counter_log.append(i)

                        if con_log == 1:
                            common_part = list(set(counter_log) & set(counter_site))
                            if not common_part:
                                messagebox.showerror("!!!", "Check the correctness of the entered data")
                                wp()

                            counter_lines = 0
                            taking_data()
                            with open('test.txt') as f:
                                lines = f.readlines()
                                for i in range(len(lines)):
                                    counter_lines += 1
                            with open('test.txt', "w") as f:
                                f.write('')

                            if 1 <= int(common_part[0]) < counter_lines:
                                x = int(common_part[0]) + 1
                                new_f = lines[:int(common_part[0])] + lines[x:]
                                for i in range(len(new_f)):
                                    new_f[i] = new_f[i].replace("\n",'')

                                list_of_pass = []
                                for i in range(len(new_f)):
                                    a = encrypt(new_f[i], key_enc)
                                    list_of_pass.append(a)

                                with sq.connect("saper_log.db") as con:
                                    cur = con.cursor()
                                    d_n = f"DELETE FROM users_pass"
                                    cur.execute(d_n)
                                    for i in range(len(list_of_pass)):
                                        a = list_of_pass[i]['cipher_text']
                                        b = list_of_pass[i]['salt']
                                        c = list_of_pass[i]['nonce']
                                        d = list_of_pass[i]['tag']
                                        cur.execute(f"INSERT INTO users_pass VALUES('{a}','{b}','{c}','{d}')")
                                with open('test.txt', "w") as f:
                                    f.write('')

                                    for i in range(len(new_f)):
                                        f.write(new_f[i])
                                    get_log_site()

                            elif int(common_part[0]) == 0:
                                new_f = lines[1:]
                                for i in range(len(new_f)):
                                    new_f[i] = new_f[i].replace("\n",'')
                                list_of_pass = []
                                for i in range(len(new_f)):
                                    a = encrypt(new_f[i], key_enc)
                                    list_of_pass.append(a)

                                with sq.connect("saper_log.db") as con:
                                    cur = con.cursor()
                                    cur.execute("""DELETE FROM users_pass""")
                                    for i in range(len(list_of_pass)):
                                        a = list_of_pass[i]['cipher_text']
                                        b = list_of_pass[i]['salt']
                                        c = list_of_pass[i]['nonce']
                                        d = list_of_pass[i]['tag']
                                        cur.execute(f"INSERT INTO users_pass VALUES('{a}','{b}','{c}','{d}')")
                                with open('test.txt', "w") as f:
                                    f.write('')

                                    for i in range(len(new_f)):
                                        f.write(new_f[i])
                                    get_log_site()
                            elif int(common_part[0]) == counter_lines:
                                new_f = lines[:int(common_part[0])]
                                for i in range(len(new_f)):
                                    new_f[i] = new_f[i].replace("\n",'')
                                list_of_pass = []
                                for i in range(len(new_f)):
                                    a = encrypt(new_f[i], key_enc)
                                    list_of_pass.append(a)

                                with sq.connect("saper_log.db") as con:
                                    cur = con.cursor()
                                    cur.execute("""DELETE FROM users_pass""")
                                    for i in range(len(list_of_pass)):
                                        a = list_of_pass[i]['cipher_text']
                                        b = list_of_pass[i]['salt']
                                        c = list_of_pass[i]['nonce']
                                        d = list_of_pass[i]['tag']
                                        cur.execute(f"INSERT INTO users_pass VALUES('{a}','{b}','{c}','{d}')")
                                with open('test.txt', "w") as f:
                                    f.write('')

                                    for i in range(len(new_f)):
                                        f.write(new_f[i])
                                        get_log_site()
                            else:
                                print('Error')




                        elif con_log == 0:
                            messagebox.showerror("!!!", "There is no this login for that site")
                            wp()
                        else:
                            print('Error')
                elif con_site == 0:
                    messagebox.showerror("!!!", "There is no this site")
                    clear()
                    Label(font=font_for_all, text="Do You want to add password for this site?", bg=main_colour, height=2).grid(
                        row=0, column=0,
                        columnspan=2,
                        sticky='wens')
                    Button(font=font_for_all, text="Yes", command=lambda: add_password(), bg=colour_for_yes_no).grid(row=1, column=1,
                                                                                               sticky='wens')
                    Button(font=font_for_all, text="No", command=lambda: wp(), bg=colour_for_yes_no).grid(row=1, column=0, sticky='wens')
                else:
                    print('Error')
            else:
                print('Error')

        def get_log_site():
            clear()

            with open('test.txt') as f:  # count lines

                line_count = 0
                for _ in f:
                    line_count += 1  #

            def adding1():

                clear()



                Label(font=font_for_all, text="Website: ", bg=main_colour).grid(row=1, column=0, sticky='wens')
                ent_site = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
                ent_site.grid(row=1, column=1, sticky='wens')
                Label(font=font_for_all, text="Login: ", bg=main_colour).grid(row=2, column=0, sticky='wens')
                ent_login = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
                ent_login.grid(row=2, column=1, sticky='wens')
                Label(font=font_for_all, text="Password: ", bg=main_colour).grid(row=3, column=0, sticky='wens')
                ent_password = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
                ent_password.grid(row=3, column=1, sticky='wens')
                bt_back = Button(font=font_for_all, text="Back", width=49, command=lambda: wp(), bg=colour_for_back)
                bt_back.grid(row=4, column=0, sticky='wens')
                bt_ent = Button(font=font_for_all, bg=colour_for_back,text="Enter", width=50,
                                command=lambda: writing(ent_site.get(), ent_login.get(), ent_password.get()))
                bt_ent.grid(row=4, column=1, sticky='wens')

            adding1()

            def writing(web, log, pas):
                if web == '':
                    messagebox.showerror("!!!", "Fill in all the fields")
                    adding1()

                elif log == '':
                    messagebox.showerror("!!!", "Fill in all the fields")
                    adding1()

                elif pas == '':
                    messagebox.showerror("!!!", "Fill in all the fields")
                    adding1()

                else:
                    if True:
                        taking_data()
                        with open('test.txt') as f:
                            lines = f.readlines()
                        with open('test.txt', "w") as f:
                            f.write('')
                        for i in range(len(lines)):
                            in_pass = lines[i].index("password")
                            line = lines[i][:in_pass]

                            if web + ',' in str(line.split()[3]) and log + ',' in str(line.split()[5]):
                                messagebox.showerror("!!!", 'This data is already there!')
                                wp()
                                break
                        else:
                            with open('test.txt', 'a') as f:
                                line = f"Name of website: {web}, login: {log}, password: {pas}"
                                print(line, file=f, end="\n")
                            wr_in_db(web, log, pas)
                            wp()

    def delete_one_pass():
        clear()

        Label(font=font_for_all, text="What password do you want to delete?", bg=main_colour).grid(columnspan=2,
                                                                                                   sticky='wens')
        Label(font=font_for_all, text="Name of website:", bg=main_colour).grid(row=1, sticky='wens')
        d_site = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
        d_site.grid(row=1, column=1, sticky='wens')

        bt_back = Button(font=font_for_all, text="Enter", width=23, command=lambda: getting_d_pass(),
                         bg=colour_for_back)
        bt_back.grid(row=2, column=1, sticky='wens')
        bt_back = Button(font=font_for_all, text="Back", width=23, command=lambda: wp(), bg=colour_for_back)
        bt_back.grid(row=2, column=0, sticky='wens')

        def getting_d_pass():
            counter_log = []
            counter_site = []

            if d_site.get() == "":
                messagebox.showerror("!!!", "Fill in the field")
                delete_one_pass()

            elif d_site.get() != "":
                delete_site = d_site.get()
                taking_data()
                with open('test.txt') as f:
                    lines = f.readlines()
                with open('test.txt', "w") as f:
                    f.write('')
                lines_s = []
                con_site = 0
                for i in range(len(lines)):
                    try:
                        s_i = lines[i].index(',')
                        lines_s.append(lines[i][:s_i].split())
                        if delete_site in lines_s[i]:
                            con_site = 1
                            counter_site.append(i)

                    except ValueError:
                        clear()
                        messagebox.showinfo("", "There is not at least one password.")
                        Label(font=font_for_all, text="Do You want to add password?", bg=main_colour, height=2).grid(row=0,
                                                                                                           column=0,
                                                                                                           columnspan=2,
                                                                                                           sticky='wens')
                        Button(font=font_for_all, text="Yes", command=lambda: add_password()).grid(row=1, column=1,
                                                                                                   sticky='wens',
                                                                                                   bg=colour_for_yes_no)
                        Button(font=font_for_all, text="No", command=lambda: wp()).grid(row=1, column=0, sticky='wens',
                                                                                        bg=colour_for_yes_no)

                if not lines:
                    clear()
                    with open('test.txt', "w") as f:
                        f.write('')
                    messagebox.showinfo("", "There is not at least one password.")
                    wp()
                elif lines != [] and con_site == 1:
                    clear()
                    Label(font=font_for_all, text="Enter login of this password", bg=main_colour).grid(
                        columnspan=3,
                        sticky='wens')
                    Label(font=font_for_all, text="Login:", bg=main_colour).grid(row=1, column=1, sticky='wens')
                    d_login = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
                    d_login.grid(row=1, column=2, sticky='wens')

                    bt_ent = Button(font=font_for_all, text="Enter", width=23, command=lambda: d_log_final(), bg=colour_for_back)
                    bt_ent.grid(row=2, column=2, sticky='wens')
                    bt_back = Button(font=font_for_all, text="Back", width=23, command=lambda: wp(), bg=colour_for_back)
                    bt_back.grid(row=2, column=1, sticky='wens')

                    def d_log_final():

                        log_for_delet = d_login.get()
                        if log_for_delet == "":
                            messagebox.showerror("!!!", "Fill in the field")
                            getting_d_pass()
                        taking_data()
                        with open('test.txt') as f:
                            lines = f.readlines()
                        with open('test.txt', "w") as f:
                            f.write('')
                        lines_l = []
                        con_log = 0
                        for i in range(len(lines)):
                            log_in_line = str(lines[i]).split(',')
                            lines_l.append(log_in_line[1])
                            login_only = str(lines_l[i]).split(" ")

                            if str(log_for_delet) == str(login_only[2]):
                                con_log = 1
                                counter_log.append(i)

                        if con_log == 1:
                            common_part = list(set(counter_log) & set(counter_site))
                            if not common_part:
                                messagebox.showerror("!!!", "Check the correctness of the entered data")
                                wp()

                            counter_lines = 0
                            taking_data()
                            with open('test.txt') as f:
                                lines = f.readlines()
                            with open('test.txt', "w") as f:
                                f.write('')
                                for i in range(len(lines)):
                                    counter_lines += 1

                            if 1 <= int(common_part[0]) < counter_lines:
                                x = int(common_part[0]) + 1
                                new_f = lines[:int(common_part[0])] + lines[x:]

                                for i in range(len(new_f)):
                                    new_f[i] = new_f[i].replace("\n",'')

                                list_of_pass = []
                                for i in range(len(new_f)):
                                    a = encrypt(new_f[i], key_enc)
                                    list_of_pass.append(a)

                                with sq.connect("saper_log.db") as con:
                                    cur = con.cursor()
                                    d_n = f"DELETE FROM users_pass"
                                    cur.execute(d_n)

                                    for i in range(len(list_of_pass)):
                                        a = list_of_pass[i]['cipher_text']
                                        b = list_of_pass[i]['salt']
                                        c = list_of_pass[i]['nonce']
                                        d = list_of_pass[i]['tag']
                                        cur.execute(f"INSERT INTO users_pass VALUES('{a}','{b}','{c}','{d}')")
                                with open('test.txt', "w") as f:
                                    f.write('')

                                    for i in range(len(new_f)):
                                        f.write(new_f[i])
                                    messagebox.showinfo("", "This password was deleted!")

                            elif int(common_part[0]) == 0:
                                new_f = lines[1:]

                                for i in range(len(new_f)):
                                    new_f[i] = new_f[i].replace("\n",'')

                                list_of_pass = []
                                for i in range(len(new_f)):
                                    a = encrypt(new_f[i], key_enc)
                                    list_of_pass.append(a)

                                with sq.connect("saper_log.db") as con:
                                    cur = con.cursor()
                                    list_of_pass = []
                                    for i in range(len(new_f)):
                                        a = encrypt(new_f[i], key_enc)
                                        list_of_pass.append(a)

                                    cur.execute("""DELETE FROM users_pass""")
                                    for i in range(len(list_of_pass)):
                                        a = list_of_pass[i]['cipher_text']
                                        b = list_of_pass[i]['salt']
                                        c = list_of_pass[i]['nonce']
                                        d = list_of_pass[i]['tag']
                                        cur.execute(f"INSERT INTO users_pass VALUES('{a}','{b}','{c}','{d}')")
                                with open('test.txt', "w") as f:
                                    f.write('')

                                    for i in range(len(new_f)):
                                        f.write(new_f[i])
                                    messagebox.showinfo("", "This password was deleted!")
                            elif int(common_part[0]) == counter_lines:
                                new_f = lines[:int(common_part[0])]
                                for i in range(len(new_f)):
                                    new_f[i] = new_f[i].replace("\n",'')

                                list_of_pass = []
                                for i in range(len(new_f)):
                                    a = encrypt(new_f[i], key_enc)
                                    list_of_pass.append(a)

                                with sq.connect("saper_log.db") as con:
                                    cur = con.cursor()
                                    cur.execute(
                                        """DELETE FROM users_pass""")
                                    for i in range(len(list_of_pass)):
                                        a = list_of_pass[i]['cipher_text']
                                        b = list_of_pass[i]['salt']
                                        c = list_of_pass[i]['nonce']
                                        d = list_of_pass[i]['tag']
                                        cur.execute(f"INSERT INTO users_pass VALUES('{a}','{b}','{c}','{d}')")
                                with open('test.txt', "w") as f:
                                    f.write('')

                                    for i in range(len(new_f)):
                                        f.write(new_f[i])
                                    messagebox.showinfo("", "This password was deleted!")
                            else:
                                print('Error')
                            wp()



                        elif con_log == 0:
                            messagebox.showerror("!!!", "There is no this login for that site")
                            wp()
                        else:
                            print('Error')
                elif con_site == 0:
                    messagebox.showerror("!!!", "There is no this site")
                    clear()
                    wp()
                else:
                    print('Error')
            else:
                print('Error')

    def add_password():
        clear()
        location()
        with open('test.txt') as f:  # count lines

            line_count = 0
            for _ in f:
                line_count += 1

        clear()

        try:
            def adding():

                clear()
                location()
                Label(font=font_for_all, text="Website: ", bg=main_colour).grid(row=0, column=0, sticky='wens')
                ent_site = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
                ent_site.grid(row=0, column=1, sticky='')
                Label(font=font_for_all, text="Login: ", bg=main_colour).grid(row=1, column=0, sticky='wens')
                ent_login = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
                ent_login.grid(row=1, column=1, sticky='')
                Label(font=font_for_all, text="Password: ", bg=main_colour).grid(row=2, column=0, sticky='wens')
                ent_password = Entry(root_acc, bg=colour_for_entry, font=font_for_all)
                ent_password.grid(row=2, column=1, sticky='')
                bt_back = Button(font=font_for_all, text="Back", command=lambda: wp(), bg=colour_for_back)
                bt_back.grid(row=3, column=0, sticky='wens')
                bt_ent = Button(font=font_for_all, text="Enter",
                                command=lambda: writing(ent_site.get(), ent_login.get(), ent_password.get()), bg=colour_for_back)
                bt_ent.grid(row=3, column=1, sticky='wens')


            def writing(web, log, pas):

                if web == '':
                    messagebox.showerror("!!!", "Fill in all the fields")
                    add_password()

                elif log == '':
                    messagebox.showerror("!!!", "Fill in all the fields")
                    add_password()

                elif pas == '':
                    messagebox.showerror("!!!", "Fill in all the fields")
                    add_password()

                else:
                    if True:
                        taking_data()
                        with open('test.txt') as f:
                            lines = f.readlines()
                        with open('test.txt', "w") as f:
                            f.write('')
                        check = 0
                        for i in range(len(lines)):
                            if lines:

                                in_pass = lines[i].index("password")
                                line = lines[i][:in_pass]

                                if web + ',' in str(line.split()[3]) and log + ',' in str(line.split()[5]):
                                    messagebox.showerror("!!!", 'This data is already there!')
                                    wp()
                                    check += 1
                                    break
                        if check == 0:
                            wr_in_db(web, log, pas)
                            wp()

            adding()
        except:
            messagebox.showinfo("!!!", """You can not use symbols or letters!!!""")
            add_password()

    def print_password():
        clear()
        with open('test.txt', "w") as f:
            f.write('')
        taking_data()
        with open('test.txt') as f:
            lines = f.readlines()

        with open('test.txt', "w") as f:
            f.write('')
            ml = "The list of passwords:"
            for i in range(len(lines)):

                a = lines[i]
                if len(a) > len(ml):
                    ml = a

            list_of_passwords = Listbox(height=len(lines)+1, width=len(ml), font=font_for_all, bg=colour_for_entry)

            # try:
            if not lines:
                messagebox.showinfo("", "There is not at least one password.")
                Label(font=font_for_all, text="Do You want to add password?", bg=main_colour, height=2).grid(row=0, column=0,
                                                                                                   columnspan=2,
                                                                                                   sticky='wens')
                Button(font=font_for_all, text="Yes", command=lambda: add_password(), bg=colour_for_yes_no).grid(row=1, column=1,
                                                                                           sticky='wens')
                Button(font=font_for_all, bg=colour_for_yes_no, text="No", command=lambda: first_choice()).grid(row=1, column=0,
                                                                                          sticky='wens')

            else:
                s = " " * (len(ml) // 2)
                list_of_passwords.insert(1, s + 'The list of passwords:')

                for i in range(len(lines)):
                    a = lines[i]

                    list_of_passwords.insert(i + 1, a)

                list_of_passwords.grid(row=0, column=0, sticky='wens')

                bt_ba = Button(font=font_for_all, text="Back", command=lambda: wp(), bg=colour_for_back)
                bt_ba.grid(row=1, column=0, columnspan=2, sticky='wens')

    def clear_password():
        clear()
        location()
        Label(font=font_for_all, text="Are you sure?", bg=main_colour).grid(columnspan=2, sticky='wens')
        bt_ba = Button(font=font_for_all, text="No", command=lambda: wp(), bg=colour_for_yes_no)
        bt_ba.grid(row=1, sticky='wens')
        bt_sure = Button(font=font_for_all, text="Yes", command=lambda: cp(), bg=colour_for_yes_no)
        bt_sure.grid(row=1, column=1, sticky='wens')

        def cp():
            with sq.connect("saper_log.db") as con:
                cur = con.cursor()
                cur.execute("DELETE FROM users_pass")

            with open('test.txt', "w") as f:
                f.write('')
            messagebox.showinfo("", "All passwords were deleted")
            first_choice()


def first_choice():
    clear()  # очищение

    Label(font=font_for_all, text="Choose action: generate password or work with the list of passwords.",
          bg=main_colour, height=2).grid(row=0,
                               column=0,
                               columnspan=2,
                               sticky='wens')
    bt_gp = Button(font=font_for_all, bg=colour_for_back, text="Generate password", command=lambda: generation_pass())
    bt_gp.grid(row=1, column=0, sticky='wens')
    bt_wp = Button(font=font_for_all, bg=colour_for_back, text="Work with the list of passwords", command=lambda: wp())
    bt_wp.grid(row=1, column=1, sticky='wens')


def account_login(window):  # входим в аккаунт
    clear()  # очищение

    # вход

    Label(font=font_for_all, text="Login: ", bg=main_colour).grid(row=0, column=0, sticky='wens')
    login_log = Entry(window, bg=colour_for_entry, font=font_for_all)
    login_log.grid(row=0, column=1, sticky='wens')
    Label(font=font_for_all, text="Enter the password ", bg=main_colour).grid(row=1, column=0, sticky='wens')
    log_pas = Entry(window, show="*", bg=colour_for_entry, font=font_for_all)
    log_pas.grid(row=1, column=1, sticky='wens')
    bt_log = Button(font=font_for_all, text="Log in", command=lambda: passing_login(), bg=colour_for_back)
    bt_log.grid(row=2, column=1, sticky='wens')
    bt_back = Button(font=font_for_all, text="Back", command=lambda: do_u_have_account(), bg=colour_for_back)
    bt_back.grid(row=2, column=0, sticky='wens')
    bt_back = Button(font=font_for_all, text="Forgot password", command=lambda: do_u_want_regis(root_acc),
                     bg=colour_for_back)
    bt_back.grid(row=5, column=0, sticky='wens', columnspan=2)

    def passing_login():
        lo = login_log.get()
        pa = log_pas.get()
        counter = 1
        if not lo or not pa:
            counter = 0
            messagebox.showerror("!!!", " You can't use symbols or letters or nothing!!!")
        p_check = str(lo) + str(pa)

        with sq.connect("saper_log.db") as con:
            cur = con.cursor()
            cur.execute("SELECT * FROM users_reg")
            p_f = cur.fetchall()
            c = 1
            if p_f:
                dict_f = {'cipher_text': p_f[0][0], 'salt': p_f[0][1], 'nonce': p_f[0][2], 'tag': p_f[0][3]}
            else:
                c = 0
        if c == 0 and counter != 0:
            messagebox.showerror('!!!', 'You have not account!')
            do_u_want_regis(root_acc)

        else:
            a = decrypt(dict_f, key_enc)
            if a == p_check:
                first_choice()
            else:
                messagebox.showerror("Error", "Wrong password!")


def do_u_want_regis(window):
    clear()  # очищение

    # asking
    Label(font=font_for_all, text="Do You want to register?(It deletes all data!)", bg=main_colour, height=2).grid(row=0,
                                                                                                         column=0,
                                                                                                         sticky='wens',
                                                                                                         columnspan=2)
    bt_yes_reg = Button(font=font_for_all, text="Yes", command=lambda: registration(root_acc), bg=colour_for_yes_no)
    bt_yes_reg.grid(row=1, column=1, sticky='wens')
    bt_no_reg = Button(font=font_for_all, text="No", command=lambda: window.destroy(), bg=colour_for_yes_no)
    bt_no_reg.grid(row=1, column=0, sticky='wens')
    bt_back = Button(font=font_for_all, text="Back", command=lambda: do_u_have_account(), bg=colour_for_back)
    bt_back.grid(row=2, column=0, sticky='wens', columnspan=2)


def registration(window):
    clear()  # очищение
    with sq.connect("saper_log.db") as con:
        cur = con.cursor()
        cur.execute("""DROP TABLE IF EXISTS users_reg""")
    with sq.connect("saper_log.db") as con:
        cur = con.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users_reg (

            cipher_text TEXT,
            salt TEXT,
            nonce TEXT,
            tag TEXT
            )""")

    # Регистрация

    Label(font=font_for_all, text="Please register", bg=main_colour).grid(row=0, column=0, columnspan=2, sticky='wens')
    Label(font=font_for_all, text="Login: ", bg=main_colour).grid(row=1, column=0, sticky='wens')
    regis_log = Entry(window, bg=colour_for_entry, font=font_for_all)
    regis_log.grid(row=1, column=1, sticky='wens')
    Label(font=font_for_all, text="Enter password: ", bg=main_colour).grid(row=2, column=0, sticky='wens')
    regis_pas = Entry(window, bg=colour_for_entry, font=font_for_all)
    regis_pas.grid(row=2, column=1, sticky='wens')
    Label(font=font_for_all, text="Enter the password again: ", bg=main_colour).grid(row=3, column=0, sticky='wens')
    regis_pas2 = Entry(window, show="*", bg=colour_for_entry, font=font_for_all)
    regis_pas2.grid(row=3, column=1, sticky='wens')
    bt_back = Button(font=font_for_all, text="Back", command=lambda: do_u_have_account(), bg=colour_for_back)
    bt_back.grid(row=4, column=0, sticky='wens')
    bt_reg = Button(font=font_for_all, text="Register", command=lambda: checking(),bg=colour_for_back)
    bt_reg.grid(row=4, column=1, sticky='wens')

    def checking():
        if regis_pas2.get() != regis_pas.get():
            messagebox.showerror("!!!", "Passwords mismatch")
            registration(root_acc)

        elif regis_pas2.get() == "" or regis_log.get() == "":
            messagebox.showerror("!!!", "Fill in all the fields")
            registration(root_acc)
        else:
            save_reg(regis_log.get(), regis_pas.get())


def do_u_have_account():  # спрашиваем есть ли акк
    clear()  # очищение
    location()

    text1 = Label(font=font_for_all, text="Do you have account?", height=2, bg=main_colour)
    text1.grid(row=0, column=0, columnspan=2, sticky='wens')
    bt_yes = Button(font=font_for_all, text="Yes", command=lambda: account_login(root_acc), bg=colour_for_yes_no)
    bt_yes.grid(row=1, column=1, sticky='wens')
    bt_no = Button(font=font_for_all, text="No", command=lambda: do_u_want_regis(root_acc), bg=colour_for_yes_no)
    bt_no.grid(row=1, column=0, sticky='wens')


# creating window


root_acc = Tk()


root_acc.geometry("+-100+-10000000")
try:
    root_acc.iconbitmap('lock.ico')
except:
    pass
root_acc.config(bg=main_colour)
# C = Canvas(root_acc, bg="black", height=250, width=300)
# filename = PhotoImage(file ='matrix.png')
# background_label = Label(root_acc, image=filename)
# background_label.place(x=0, y=0, relwidth=1, relheight=1)
# C.grid()
#

def location():
    wid = int((root_acc.winfo_screenwidth())//3)
    heig =int((root_acc.winfo_screenheight())//3)
    if wid >= 480 or heig >= 480:
        root_acc.geometry(f"+{wid}+{heig}")

root_acc.resizable(False, False)
root_acc.title("Password manager")

do_u_have_account()


root_acc.mainloop()