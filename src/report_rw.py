import hashlib
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from sql_helper import *

def write_report(config_file, report_file, report_text, results_csv, pwd=None):
    if not pwd:
        with open(report_file, 'w') as wf:
            wf.write(report_text)
    else:
        pwd_hash = hashlib.sha256(
                    hashlib.sha3_512(
                     pwd.encode()).hexdigest().encode()).digest()
    iv = get_random_bytes(16)

    report_text = report_text+str(iv)+results_csv

    if pwd:
        text = report_text.encode()
        pad = 16 - (len(text) % 16)
        mode = AES.MODE_CBC
        encryptor = AES.new(pwd_hash, mode, IV=iv)
        ciphertext = encryptor.encrypt(text+get_random_bytes(pad))
        with open(report_file, "wb") as wf:
            wf.write(ciphertext)

    con = sql_connection()
    sql_table(con)
    if pwd:
        row = [config_file, report_file, pwd_hash, iv, pad]
    else:
        row = [config_file, report_file, report_text, iv, -1]
    sql_insert(con, row)
    con.close()

def read_report(report_file, pwd=None):
    if pwd:
        pwd_hash = hashlib.sha256(
                    hashlib.sha3_512(
                     pwd.encode()).hexdigest().encode()).digest()

        mode = AES.MODE_CBC
    
    con = sql_connection()
    row = sql_fetch(con, report_file)
    con.close()
    if not row:
        return None
    if not pwd:
        iv = row[3]
        plain, csv = row[2].split(str(iv))
        return plain, csv
    stored_pwd = row[2]
    iv = row[3]
    pad = row[4]

    if stored_pwd == pwd_hash:
        with open(report_file, "rb") as rf:
            decryptor = AES.new(pwd_hash, mode, IV=iv)
            plain = decryptor.decrypt(rf.read())[:-pad].decode()
            plain, csv = plain.split(str(iv))
            return plain, csv
    else:
        return None

def check_report(report_file):
    con = sql_connection()
    row = sql_fetch(con, report_file)
    con.close()
    if row[-1] == -1:
        return False
    return True
