#!/usr/bin/python3
# Import Modules
try:
    import os,sys,time,random,hashlib,passlib,zlib,readline,platform
    from passlib.hash import mysql323,mysql41,mssql2000,mssql2005,des_crypt,bsdi_crypt,bigcrypt,crypt16,md5_crypt,sha1_crypt,sha256_crypt,sha512_crypt,sun_md5_crypt,apr_md5_crypt,phpass,cta_pbkdf2_sha1,dlitz_pbkdf2_sha1,cta_pbkdf2_sha1,django_pbkdf2_sha1,django_pbkdf2_sha256,grub_pbkdf2_sha512,scram,bsd_nthash,oracle11,lmhash,nthash,cisco_type7,fshp
except Exception as F:
    exit("\x1b[1;31m   [!] \x1b[0;32m%s\x1b[0;39m"%(F)+"\x1b[0;39m")
# Color
A = "\x1b[1;32m"
B = "\x1b[1;31m"
C = "\x1b[1;33m"
D = "\x1b[1;36m"
E = "\x1b[0;39m"
rand = (A,B,C,D)
W = random.choice(rand)
# Adaptor
name = platform.system()
if name == "Windows":
    clr = "cls"
else:
    clr = "clear"
if sys.version_info[0] != 3:
    exit(B+"   [!] "+A+"This tool work only on python3!"+E)
else:
    pass
# Banner
BR = W+"""
	 _   _           _
	| | | | __ _ ___| |__   ___ _ __
	| |_| |/ _` / __| '_ \ / _ \ '__|
	|  _  | (_| \__ \ | | |  __/ |
	|_| |_|\__,_|___/_| |_|\___|_|
"""
# Hash
try:
    os.system(clr)
    print(BR)
    x = input(C+"   [+] "+D+"String to hash: "+E)
    x = x.encode("utf-8")
    print(C+"   [!] "+D+"Generating hash please wait"+E+" ...\n")
    # MD4
    m = hashlib.new("md4")
    m.update(x)
    md4 = m.hexdigest()
    print(B+"   [01] "+A+"MD4 : "+E+md4)
    # MD5
    md5 = hashlib.md5(x).hexdigest()
    print(B+"   [02] "+A+"MD5 : "+E+md5)
    # SHA1
    sha1 = hashlib.sha1(x).hexdigest()
    print(B+"   [03] "+A+"SHA1 : "+E+sha1)
    # SHA224
    sha224 = hashlib.sha224(x).hexdigest()
    print(B+"   [04] "+A+"SHA224 : "+E+sha224)
    # SHA256
    sha256 = hashlib.sha256(x).hexdigest()
    print(B+"   [05] "+A+"SHA256 : "+E+sha256)
    # SHA384
    sha384 = hashlib.sha384(x).hexdigest()
    print(B+"   [06] "+A+"SHA384 : "+E+sha384)
    # SHA512
    sha512 = hashlib.sha512(x).hexdigest()
    print(B+"   [07] "+A+"SHA512 : "+E+sha512)
    # RIPEMD160
    m = hashlib.new("ripemd160")
    m.update(x)
    ripemd160 = m.hexdigest()
    print(B+"   [08] "+A+"RIPEMD160 : "+E+ripemd160)
    # WHIRLPOOL
    m = hashlib.new("whirlpool")
    m.update(x)
    whirl = m.hexdigest()
    print(B+"   [09] "+A+"WHIRLPOOL : "+E+whirl)
    # CRC32
    h = zlib.crc32(x)
    crc32 = "%08X" % (h & 0xffffffff,)
    print(B+"   [10] "+A+"CRC32 : "+E+crc32.lower())
    # ADLER32
    h = zlib.adler32(x)
    adler32 = "%08X" % (h & 0xffffffff,)
    print(B+"   [11] "+A+"ADLER32 : "+E+adler32.lower())
    # MySQL323
    mysql323 = mysql323.hash(x)
    print(B+"   [12] "+A+"MySQL 3.2.3 : "+E+mysql323)
    # MySQL41
    mysql41 = mysql41.hash(x)
    print(B+"   [13] "+A+"MySQL 4.1 : "+E+mysql41)
    # MSSQL2000
    mssql2000 = mssql2000.hash(x)
    print(B+"   [14] "+A+"MSSQL 2000 : "+E+mssql2000)
    # MSSQL2005
    mssql2005 = mssql2005.hash(x)
    print(B+"   [15] "+A+"MSSQL 2005 : "+E+mssql2005)
    # DES Crypt
    des_crypt = des_crypt.hash(x)
    print(B+"   [16] "+A+"DES Crypt : "+E+des_crypt)
    # BSDi Crypt
    bsdi_crypt = bsdi_crypt.hash(x)
    print(B+"   [17] "+A+"BSDi Crypt : "+E+bsdi_crypt)
    # BIGCrypt
    big_crypt = bigcrypt.hash(x)
    print(B+"   [18] "+A+"BIGCrypt : "+E+big_crypt)
    # Crypt16
    crypt16 = crypt16.hash(x)
    print(B+"   [19] "+A+"Crypt16 : "+E+crypt16)
    # MD5 Crypt
    md5_crypt = md5_crypt.hash(x)
    print(B+"   [20] "+A+"MD5 Crypt : "+E+md5_crypt)
    # SHA1 Crypt
    sha1_crypt = sha1_crypt.hash(x)
    print(B+"   [21] "+A+"SHA1 Crypt : "+E+sha1_crypt)
    # SHA256 Crypt
    sha256_crypt = sha256_crypt.hash(x)
    print(B+"   [22] "+A+"SHA256 Crypt : "+E+sha256_crypt)
    # SHA512 Crypt
    sha512_crypt = sha512_crypt.hash(x)
    print(B+"   [23] "+A+"SHA512 Crypt : "+E+sha512_crypt)
    # Sun MD5 Crypt
    smd5 = sun_md5_crypt.hash(x)
    print(B+"   [24] "+A+"Sun MD5 Crypt : "+E+smd5)
    # Apr MD5 Crypt
    amd5 = apr_md5_crypt.hash(x)
    print(B+"   [25] "+A+"Apr MD5 Crypt : "+E+amd5)
    # PHPASS
    phpass = phpass.hash(x)
    print(B+"   [26] "+A+"PHPASS : "+E+phpass)
    # Cryptacular"s PBKDF2
    cryptacular = cta_pbkdf2_sha1.hash(x)
    print(B+"   [27] "+A+"Cryptacular\"s PBKDF2 : "+E+cryptacular)
    # Dlitz PBKDF2 SHA1
    dlitz_pbkdf2_sha1 = dlitz_pbkdf2_sha1.hash(x)
    print(B+"   [28] "+A+"Dlitz PBKDF2 SHA1 : "+E+dlitz_pbkdf2_sha1)
    # Atlassian"s PBKDF2 SHA1
    atl_pbkdf2_sha1 = cta_pbkdf2_sha1.hash(x)
    print(B+"   [29] "+A+"Atlassian's PBKDF2 SHA1 : "+E+atl_pbkdf2_sha1)
    # Django PBKDF2 SHA1
    django_pbkdf2_sha1 = django_pbkdf2_sha1.hash(x)
    print(B+"   [30] "+A+"Django PBKDF2 SHA1 : "+E+django_pbkdf2_sha1)
    # Django PBKDF2 SHA256
    django_pbkdf2_sha256 = django_pbkdf2_sha256.hash(x)
    print(B+"   [31] "+A+"Django PBKDF2 SHA256 : "+E+django_pbkdf2_sha256)
    # Grub"s PBKDF2 SHA512
    grub_pbkdf2_sha512 = grub_pbkdf2_sha512.hash(x)
    print(B+"   [32] "+A+"Grub's PBKDF2 SHA512 : "+E+grub_pbkdf2_sha512)
    # SCRAM Hash
    scram = scram.hash(x)
    print(B+"   [33] "+A+"SCRAM Hash : "+E+scram)
    # FreeBSD NT Hash
    bsd = bsd_nthash.hash(x)
    print(B+"   [34] "+A+"BSD NT Hash : "+E+bsd)
    # Oracle11
    oracle = oracle11.hash(x)
    print(B+"   [35] "+A+"Oracle 11 : "+E+oracle)
    # LanManager Hash
    lm = lmhash.hash(x)
    print(B+"   [36] "+A+"LanManager Hash : "+E+lm)
    # Windows NT Hash
    nt = nthash.hash(x)
    print(B+"   [37] "+A+"Windows NT Hash : "+E+nt)
    # Cisco Type 7
    ct7 = cisco_type7.hash(x)
    print(B+"   [38] "+A+"Cisco Type 7 : "+E+ct7)
    # FSHP
    fshp = fshp.hash(x)
    print(B+"   [39] "+A+"FSHP : "+E+fshp)
    # Succes
    print(C+"\n   [!] "+D+"Succes generate all hash "+E+"^_^")
    sys.exit()
except KeyboardInterrupt or EOFError:
    print(B+"\n   [!] "+A+"Exiting "+E+"...")
    time.sleep(0.1)
    sys.exit()
except UnicodeEncodeError:
    print(B+"   [!] "+A+"This value is not support for now."+E)
    sys.exit()
except Exception as F:
    exit(B+"   [!] \x1b[0;32m%s"%(F)+E)
