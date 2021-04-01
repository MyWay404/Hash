#!/usr/bin/python3
# Import Modules
try:
    import os,sys,re,time,random,hashlib,binascii,argparse,progressbar,readline,urllib.request,gzip
    from passlib.hash import mysql323,mysql41,mssql2000,mssql2005,nthash,lmhash
except Exception as F:
    exit("\x1b[1;31m   [!] \x1b[1;32m%s\x1b[0;39m"%(F))
# Color
A = "\x1b[1;32m"
B = "\x1b[1;31m"
C = "\x1b[1;33m"
D = "\x1b[1;36m"
E = "\x1b[0;39m"
rand = (A,B,C,D)
W = random.choice(rand)
# Check
if sys.version_info[0] != 3:
    exit(B+"   [!] "+A+"This tool work only on python3!"+E)
else:
    pass
# Banner
__version__ = "1.0"
BR = W+"""
         ____                             _
        |  _ \  ___  ___ _ __ _   _ _ __ | |_
        | | | |/ _ \/ __| '__| | | | '_ \| __|
        | |_| |  __/ (__| |  | |_| | |_) | |_
        |____/ \___|\___|_|   \__, | .__/ \__|
                              |___/|_|
"""
# Decrypt
def decrypt():
    print(BR)
    sha512 = ("dd0ada8693250b31d9f44f3ec2d4a106003a6ce67eaa92e384b356d1b4ef6d66a818d47c1f3a2c6e8a9a9b9bdbd28d485e06161ccd0f528c8bbb5541c3fef36f")
    md = ("ae11fd697ec92c7c98de3fac23aba525")
    sha1 = ("4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333")
    sha224 = ("e301f414993d5ec2bd1d780688d37fe41512f8b57f6923d054ef8e59")
    sha384 = ("3b21c44f8d830fa55ee9328a7713c6aad548fe6d7a4a438723a0da67c48c485220081a2fbc3e8c17fd9bd65f8d4b4e6b")
    sha256 = ("2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e")
    my323 = ("5d2e19393cc5ef67")
    my41 = ("*88166B019A3144C579AC4A7131BCC3AD6FF61DA6")
    ms2000 = ("0x0100DE9B3306258B37432CAC3A6FB7C638946FA393E09C9CBC0FA8C6E03B8x1b90B1C3E7FB112A21B2304595D490")
    ms2005 = ("0x01008110620C7BD03A38A28A3D1D032059AE9F2F94F3B74397F8")
    str = input(C+"   [+] "+D+"Hash string: "+E)
    print(C+"   [+] "+D+"Checking the hash "+E+"...")
    if len(str) == len(my323) and str.isdigit() == False and str.isalpha() == False and str.isalnum() == True:
        print(B+"   [!] "+A+"Hash Type : "+E+"MySQL 3.2.3")
        type = "my323"
    elif len(str) == len(my41) and "*" in str:
        print(B+"   [!] "+A+"Hash Type : "+E+"MySQL 4.1")
        type = "my41"
    elif len(str) == len(ms2000) and "0x0" in str:
        print(C+"   [!] "+A+"Hash Type : "+E+"MSSQL 2000")
        type = "ms2000"
    elif len(str) == len(ms2005) and "0x0" in str:
        print(B+"   [!] "+A+"Hash Type : "+E+"MSSQL 2005")
        type = "ms2005"
    elif len(str) == len(sha512) and str.isdigit() == False and str.isalpha() == False and str.isalnum() == True:
        print(C+"   [!] "+D+"Check hash type:\n")
        print(B+"      [01] "+A+"WHIRLPOOL")
        print(B+"      [02] "+A+"SHA512\n")
        cek = int(input(C+"   [+] "+D+"Check type : "+E))
        if cek == "01" or cek == 1:
            print(B+"   [!] "+A+"Hash Type : "+E+"WHIRLPOOL")
            type = "whirlpool"
        elif cek == "02" or cek == 2:
            print(B+"   [!] "+A+"Hash Type : "+E+"SHA512")
            type = "sha512"
        else:
            print(B+"   [!] "+A+"Wrong choice !"+E)
            sys.exit()
    elif len(str) == len(md) and str.isdigit() == False and str.isalpha() == False and str.isalnum() == True:
        print(C+"   [!] "+D+"Check hash type:\n")
        print(B+"      [01] "+A+"MD4")
        print(B+"      [02] "+A+"MD5")
        print(B+"      [03] "+A+"Windows NT Hash")
        print(B+"      [04] "+A+"LanManager Hash")
        print(B+"      [05] "+A+"NT-LM Hash\n")
        cek = int(input(C+"   [+] "+D+"Check type: "+E))
        if cek == "01" or cek == 1:
            print(B+"   [!] "+A+"Hash Type : "+E+"MD4")
            type = "md4"
        elif cek == "02" or cek == 2:
            print(B+"   [!] "+A+"Hash Type : "+E+"MD5")
            type = "md5"
        elif cek == "03" or cek == 3:
            print(B+"   [!] "+A+"Hash Type : "+E+"Windows NT Hash")
            type = "nthash"
        elif cek == "04" or cek == 4:
            print(B+"   [!] "+A+"Hash Type : "+E+"LanManager Hash")
            type = "lmhash"
        elif cek == "05" or cek == 5:
            print(B+"   [!] "+A+"Hash Type : "+E+"NT-LM Hash")
            type = "ntlm"
        else:
            print(B+"   [!] "+A+"Wrong choice !"+E)
    elif len(str) == len(sha1) and str.isdigit() == False and str.isalpha() == False and str.isalnum() == True:
        print(C+"   [!] "+D+"Check type type:\n")
        print(B+"      [01] "+A+"SHA1")
        print(B+"      [02] "+A+"RIPEMD160\n")
        cek = int(input(C+"   [+] "+D+"Check type: "+E))
        if cek == "01" or cek == 1:
            type = "sha1"
        elif cek == "02" or cek == 2:
            print(B+"   [!] "+A+"Hash Type : "+E+"RIPEMD160")
            type = "ripemd160"
        else:
            print(B+"   [!] "+A+"Wrong choice !"+E)
            sys.exit()
    elif len(str) == len(sha224) and str.isdigit() == False and str.isalpha() == False and str.isalnum() == True:
        print(B+"   [!] "+A+"Hash Type : "+E+"SHA224")
        type = "sha224"
    elif len(str) == len(sha384) and str.isdigit() == False and str.isalpha() == False and str.isalnum() == True:
        print(B+"   [!] "+A+"Hash Type : "+E+"SHA384")
        type = "sha384"
    elif len(str) == len(sha256) and str.isdigit() == False and str.isalpha() == False and str.isalnum() == True:
        print(B+"   [!] "+A+"Hash Type : "+E+"SHA256")
        type = "sha256"
    else:
        print(B+"   [!] "+A+"Type error !"+E)
        sys.exit()
    print(B+"   [!] "+A+"Open wordlist "+E)
    print(B+"   [!] "+A+"Cracking "+E+"...\x1b[1;39m")
    file = gzip.decompress(open("wordlist.txt.gz","rb").read()).decode("utf-8")
    pbar = progressbar.ProgressBar()
    word = file.split("\n")
    if type == "my323":
        for line in pbar(word):
            line = line.strip()
            h = mysql323.hash(line)
            if h == str:
                print(B+"\n   [!] "+A+"Password found !")
                print(B+"   [!] "+A+"Password : "+E+line)
                sys.exit()
        print(B+"   [!] "+A+"Password not found !"+E)
        sys.exit()
    elif type == "my41":
        for line in pbar(word):
            line = line.strip()
            h = mysql41.hash(line)
            if h == str:
                print(B+"\n   [!] "+A+"Password found !")
                print(B+"   [!] "+A+"Password : "+E+line)
                sys.exit()
        print(B+"   [!] "+A+"Password not found !"+E)
        sys.exit()
    elif type == "ms2000":
        for line in pbar(word):
            line = line.strip()
            h = mssql2000.hash(line)
            if h == str:
                print(B+"\n   [!] "+A+"Password found !")
                print(B+"   [!] "+A+"Password : "+E+line)
                sys.exit()
        print(B+"   [!] "+A+"Password not found !"+E)
        sys.exit()
    elif type == "ms2005":
        for line in pbar(word):
            line = line.strip()
            h = mssql2005.hash(line)
            if h == str:
                print(B+"\n   [!] "+A+"Password found !")
                print(B+"   [!] "+A+"Password : "+E+line)
                sys.exit()
        print(B+"   [!] "+A+"Password not found !"+E)
        sys.exit()
    elif type == "nthash":
        for line in pbar(word):
            line = line.strip()
            h = nthash.hash(line)
            if h == str:
                print(B+"\n   [!] "+A+"Password found !")
                print(B+"   [!] "+A+"Password : "+E+line)
                sys.exit()
        print(B+"   [!] "+A+"Password not found !"+E)
        sys.exit()
    elif type == "lmhash":
        for line in pbar(word):
            line = line.strip()
            h = lmhash.hash(line)
            if h == str:
                print(B+"\n   [!] "+A+"Password found !")
                print(B+"   [!] "+A+"Password : "+E+line)
                sys.exit()
        print(B+"   [!] "+A+"Password not found !"+E)
        sys.exit()
    elif type == "ntlm":
        for line in pbar(word):
            line = line.strip()
            h = binascii.hexlify(hashlib.new("md4",line.encode("utf-16-le")).digest())
            if h == str:
                print(B+"\n   [!] "+A+"Password found !")
                print(B+"   [!] "+A+"Password : "+E+line)
                sys.exit()
        print(B+"   [!] "+A+"Password not found !"+E)
        sys.exit()
    else:
        for line in pbar(word):
            line = line.strip()
            h = hashlib.new(type)
            h.update(line.encode())
            if h.hexdigest() == str:
                print(B+"\n   [!] "+A+"Password found !")
                print(B+"   [!] "+A+"Password : "+E+line)
                sys.exit()
        print(B+"   [!] "+A+"Password not found !"+E)
        sys.exit()
if __name__ == "__main__":
    def info():
        print(C+"   [!] "+D+"List of supported hash type:\n")
        print(B+"         [01] "+A+"MD5")
        print(B+"         [02] "+A+"SHA1")
        print(B+"         [03] "+A+"SHA224")
        print(B+"         [04] "+A+"SHA256")
        print(B+"         [05] "+A+"SHA384")
        print(B+"         [06] "+A+"SHA512")
        print(B+"         [07] "+A+"RIPEMD160")
        print(B+"         [08] "+A+"WHIRLPOOL")
        print(B+"         [09] "+A+"MySQL 3.2.3")
        print(B+"         [10] "+A+"MySQL 4.1")
        print(B+"         [11] "+A+"MSSQL 2000")
        print(B+"         [12] "+A+"MSSQL 2005")
        print(B+"         [13] "+A+"Windows NT Hash")
        print(B+"         [14] "+A+"LanManager Hash")
        print(B+"         [15] "+A+"NT-LM Hash\n")
        print(C+"   [!] "+D+"Thanks you for using this tool."+E)
        sys.exit()
    def update():
        print(B+"   [!] "+A+"REMOVEING OLD WORLDLIST "+E+"...")
        os.remove("wordlist.txt.gz")
        print(B+"   [!] "+A+"DONE "+E+"...")
        print(B+"   [!] "+A+"DOWNLOADING THE WORDLIST "+E+"...\x1b[1;39m")
        url = "https://raw.githubusercontent.com/MyWay404/Hash/main/wordlist.txt.gz"
        download = urllib.request.urlopen(url)
        with open("wordlist.txt.gz","wb") as F:
            for data in download:
                F.write(data)
        F.close()
        print(B+"   [!] "+A+"DONE !!!"+E)
        sys.exit()
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,prog="Decrypt",description="Decrypt. A simple tool for decrypt hash.\nCreated on Python 3.8.0.",usage="./decrypt.py [-h] [-V] [-i] [-u]")
    parser.add_argument("-V","--version",action="store_true",dest="version",help="show version info and exit")
    parser.add_argument("-i","--info",action="store_true",dest="info",help="show list info of supported hash")
    parser.add_argument("-u","--update",action="store_true",dest="update",help="for update wordlist.txt file")
    args = parser.parse_args()
    if args.info:
        info()
    if args.version:
        print("Decrypt %s from https://github.com/MyWay404/Hash."%(__version__))
        sys.exit()
    if args.update:
        try:
            update()
        except IOError:
            exit(B+"   [!] "+A+"Error can\"t remove wordlist.txt file not exist."+E)
        except Exception as F:
            exit(B+"   [!] "+A+"%s"%(F)+E)
    if args.info is False and args.update is False:
        try:
            decrypt()
        except KeyboardInterrupt or EOFError:
            print(B+"\n   [!] "+A+"Exiting "+E+"...")
            time.sleep(0.1)
            sys.exit()
        except IOError:
            exit(B+"   [!] "+A+"Error can\"t load wordlist.txt file not exist."+E)
        except Exception as F:
           exit(B+"\n   [!] "+A+"%s"%(F)+E)
           sys.exit()
else:
    pass
