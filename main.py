from sss.sss import *


def test_dev():
    # # 1. random_number
    # for i in range(100):
    #     rd = random_number()
    #     print("rd", rd)

    # # 2. modinv
    # # v = modinv(42, 2017)  # 1969
    # a = 67356225285819719212258382314594931188352598651646313425411610888829358649431
    # v = modinv(a, PRIME)
    # print(v)
    # # 66304286696287781344919781629879750902445808730247479812988635671630372079315
    # print((a * v) % PRIME)
    # # 1

    # # 3. encode/decode
    # # number = 2020
    # # encode
    # number = 67356225285819719212258382314594931188352598651646313425411610888829358649431
    # print(number)
    # b64data = to_base64(number)
    # print(len(b64data))
    # print(b64data)  # lOpFwywpCeVAcK0/LOKG+YtW71xyj1bX06CcW7VZMFc=
    # hexdata = to_hex(number)
    # print(len(hexdata))  # 64
    # print(hexdata)  # 94ea45c32c2909e54070ad3f2ce286f98b56ef5c728f56d7d3a09c5bb5593057
    # # decode
    # numb64decode = from_base64(b64data)
    # print(numb64decode)
    # numhexdecode = from_hex(hexdata)
    # print(numhexdecode)

    # 4. split & merge
    s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    print(s)
    print(len(s))
    arr = split_secret_to_int(s)
    print(arr)
    print(in_numbers(arr, 49937119214509114343548691117920141602615245118674498473442528546336026425464))
    rs = merge_int_to_string(arr)
    print(rs)
    print(len(rs))


def test1():
    s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    print("secret:", s)
    print("secret.length:", len(s))
    # creates a set of shares
    arr = create(3, 6, s, True)
    # combines shares into secret
    s1 = combine(arr[:3], True)
    print("combines shares 1 length =", len(arr[:3]))
    print("secret:", s1)
    print("secret.length:", len(s1))

    s2 = combine(arr[3:], True)
    print("combines shares 2 length =", len(arr[3:]))
    print("secret:", s2)
    print("secret.length:", len(s2))

    s3 = combine(arr[1:5], True)
    print("combines shares 3 length =", len(arr[1:5]))
    print("secret:", s3)
    print("secret.length:", len(s3))


def test2():
    s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    print("secret:", s)
    print("secret.length:", len(s))
    # creates a set of shares
    arr = [
        "3yHo_uVUBRJJ8AiBL-3SS2OAFoe8A0lYF9PVsylFpfU=hFNCvpl0Vo9pESdgVuQs88bna5lMFgfVsixJEjT38EU=rnqFtyOaWu6ROU7LqegKRBG3hnr75Uwa3xTLRTD_Ahs=HeD7Nh0314-9m6YAaAiLKv5QiPToYd_PpSOveTPf-08=VLnVwLvMoEy19oHz7F1RuQjexvNdBB9Z_0VBFpz3-tw=FVJFrnO0LyhswtULPNUQr3j-rwPVrruAp-SrU-JDQcU=6dUlv2kHgZNYlV0ZiVhtQ_E-Vdt5Qu_74_ur8hLkTaM=oOyKYNhTd98bif9cEOVxPQCJjOh7haA63COMtGVLGDA=",
        "coKbKOpKsucIF0hLgL6r2dOJpQ52TXnqU4Y4Znc26aU=Byrn3KrQn8Rq8-F49THePjAxy1fkixnjf7H-Q82tlNY=C-17nZaq6PPDfHCDPIpmVa928rUYAXxkhop-1dhyEqg=kn_fIXrpRCh1WluMW2EQddz9Vlj7m4SlUWnSAupD6yQ=yrT7uX2bF0AEdOUFQx1sd-SAYBj4vY0wLQaXkilp9LQ=65RU1AOhohmmN5dmKChFipsCdCraLIu1I0tlfUCdtdQ=_oHtNTo71hjx5RO_BaDJq2hiZTvpQjN6-O4n6zf8F_M=bd5XjTzbwgZIoXDCeqX_lGbCAIW1kepA-j6xRChI5Co=",
        "O7As77L_0wcYIjvuL-Uod9WNAWWsB1W3iFjSVPDfgDE=bfOMBFU6n6dcMTmD7Vp67xwyUMQDLMVv3dkJfU0-GAE=N7rOnWAcjXG_SA0UZyfTi4Rv17ja5_8otHG4nbnYsUE=xhfjU2E_Zc3ldk5S5vUS3nUbHcWP_8Co0ROXF_542T8=3_XtNGxPNC_ZPRydvGdeGomiHRU1alWEFbfYPE4TFPg=hUA48-h2u6gJs4g5wDmvQzbTXQlAagBG3VjBQYGgjDI=AZHs5DhgW27YC5Tw0bW4wkbwpq7l13JNyEpR6m6PM0s=ZLA7GzYugrD-ii2h0f9kx0F8dS0TJQEJgcM1sg4KxHQ=",
        "1qi-z1_JzZq1pPaQlajigXK7ZLD49o9uEbAG0i2JPRE=F_-WklezDbbn5TwLzwgTH7y4CrdtgzHkRnoT7yGvlOc=L2ydfKaeEZAdO99MEW5z2_G73Cw17GKSjrFBrtlv91w=AVDKhDGyMJjcslpMKP796I6gMAs7Y3B5Oqqo0abpTSo=Jk2aKW6g1Ol88MXn2mZcRE7o_mjlK4L4rm7Mn-1xW4Y=PTxmdcCnxcI30aqkf1vmC96CmGovnH2G_RvtRaudmoE=vlw4fz5CHvoUteCz1KiQ4VvS_AmZqJUbMC1qIh4TTbU=uNF3vO6B7Q9nA29FFoDg5XnryRJAWPf0Fyn5-qNgorg=",
        "BvCmwKngaukEhX9PbO_mbs-kVXJZasFnCTbG1BU4uy8=D5R_MinicWA4MSUYlurfxKeMqHjXcsnB8fe6eGlWl2Q=4EqtWUErsPDEupb-lyrFBcrsDVmutZao3u7NMM0j-eE=atF3vl9wmfzGWsPtaYgmMA3K6VbEctYO0PvxLYEqhPs=yWvAcAYRiz7N08AxR7gS6FUkw5K9Fufb0TUvv6sn0Go=QnYDo7XCF0A_q4zdKLgrzSuwGxdACySdy_YyvbQXKFU=zoJeB5fBh-_JZXZh_e9_lI0VYZfj2sSmn0QU5rbDzjw=RJW7Ip7iy2E5bzLFmA0MRluWRBI_unyVeCIrxSFgnr0=",
        "H7L3h0FeMRJhlOjb4P7ujl8TU62V6BR-3hmrgeZSsqY=YIgcyaTE2i9cjWGy2KYwXG-Bihe5tVqwTDvfpGG0bjc=HaQPRVj61WadfsKTNQ_nz8Ysmuw8kbTTdtTUq4pr8ow=mral1sUzGfHO7wqBG5OjpieS8OQVcfWUGMefSmoePwM=hTgwBQUnnz5NpUjq-f5ZmFLeraoWqAUXu3FvpN2InoY=_O78YvsYo8BdIVwlixp889NAACSo1fnHjXwZ06X8LIQ=D_gDXhWQ4efiIxJPn-80PiCE1qRt89bh_IK0ZOZt9Ew=tYgTQLKfnvNrlq8fMyPnKWJ165zEuvu3lOpWnw8_Qiw="
    ]
    # combines shares into secret
    s1 = combine(arr[:3], True)
    print("combines shares 1 length =", len(arr[:3]))
    print("secret:", s1)
    print("secret.length:", len(s1))

    s2 = combine(arr[3:], True)
    print("combines shares 2 length =", len(arr[3:]))
    print("secret:", s2)
    print("secret.length:", len(s2))

    s3 = combine(arr[1:5], True)
    print("combines shares 3 length =", len(arr[1:5]))
    print("secret:", s3)
    print("secret.length:", len(s3))


def test3():
    s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    print("secret:", s)
    print("secret.length:", len(s))
    # creates a set of shares
    arr = create(3, 6, s, False)
    # combines shares into secret
    s1 = combine(arr[:3], False)
    print("combines shares 1 length =", len(arr[:3]))
    print("secret:", s1)
    print("secret.length:", len(s1))

    s2 = combine(arr[3:], False)
    print("combines shares 2 length =", len(arr[3:]))
    print("secret:", s2)
    print("secret.length:", len(s2))

    s3 = combine(arr[1:5], False)
    print("combines shares 3 length =", len(arr[1:5]))
    print("secret:", s3)
    print("secret.length:", len(s3))


def test4():
    s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    print("secret:", s)
    print("secret.length:", len(s))
    # creates a set of shares
    arr = [
        "cac78fd8a2491872833bf9049cb91f706ae7c6619c8dcd11d2b93db1a42610c8d16221744779f7d1df1152d128f1c4e665fcc7d5f9c5da8c5a3954795d14e7fa882ede5e95cc86c133369f0069086a84e7dfa36a8004f6365eebc798ac467f988c5063932ea32066270dc4c18da124f7593ef71491c9e6d7b838f33524449f47c64902a4bd32d020691044daa01dbbfdc7b3a5e8fb20d546e3eac08986e50449ef4340426e494113245e49f672151e86b9da58e122673665a807cc1c04dbe7bc0151a94de40f618b470d73f90b93ede1b7d1611b6f6cb020d9ec12cd7d7bfd471f108d6caa60e3e4c933c78863ed9b8672a37270909ceca95f16e6d3f3dde55f",
        "173a962eac9997a9cbd24fa9f664c7a4e90134985344d80332d52b099fa7dfb16ada3209a95af9732b197b1b9bd9067b5f8a0053635a4bc538d60d626576fb1d2ceb4145d68125447c7716a72db869abbe56d649f53e47316bcf9ce165008a93c03ca42840f92ff5c35433375ddf3bbcbf2a8cdffdd475c9c20733b278121adec6d35a0bc80bee9311f814bea1d9783981e042f210d459e8818df76f8b541a72825274df2d5ac29e0074396e7922849d663acdd84919e113dad867a8257d571d3f8e3644dfe790f6f0192fcad5c8735ee4658de1ae03285d721d92119aafc77ffcd9bc7e80da7b47c12ae8cfc730f397cd8533889d4fc96e7f0d4d5fc49d3db9",
        "d64848bb07b603d7f882017750c260b4c9fc067dbe97bc49903e7e9a80314dd5d77398b0adcc2e6dbba02e166f93cc15f5b0cdf982abe0879ba1f530d70c9aae0e2fd6764b88616a92c5a3e1b470c19ae94b34284343a106482c15a19381a164bdd3952c55576ad95687100c59dc857b78dfc436ce7f8525420ae273ca58619df6f952772b2e0a785a10c24b77791208bcb6d0ab8c874e7b3f53e522b50855d01566b9f20d4a69136afd25f6cbf127c34650552bf1e1b2885b83fc8fe42bbbc5c3be42dec0b98b4d72a6ff118ca4c49a3055b4bdf7b1e251f7ee61d94fc04bd6d7562dd210d806911ba055ff1f5100808cf350922d4d527058112ac36ea098a2",
        "18ad9f41e1a4076fa139da699624686a32b9388cd8931c0f9278ae705ef6693c072d1d4885034672127061f2ce28e3af65c0bcd45024420adaa9df15f6ecee61cf586adcdc7a18981d85ca0ffbd58ad4b82ab15dabf0729aa7d99ce0b4013f3b7318d191cd1450fbea27488e0c4043ba2dfcfc484bdab19cb72b389bcc947c38a1d8cabe59f8f6ce7e878a4c250996835806a354fb4a177510f6a5f2a603686f3e3e9b6c82a8073ad96f49ea5ca470ef6e560a55e74699221df3953ce8747ea461ec0d9d7435eb9526a9a73e5181873c8a05b6711314902af4cf0a9bc69336e818684510273d27752ff0b2b2977f46573033a95b77fe99e004f726633070d1b8",
        "188fd844683b4f1f3b65f03ae4624166a7f7378129c946ed9bbcb5cc23c6b77e5325340b89656394711c25c5500bcc789105ee4bbc9f1c8a3a90d261d8c29feda7647cdf1f88c918a4a4afe5af0e8820c779b3b98540571a2f8603996a0dfb8c1bce6440a7f07288fedc9fa66f86548b8ca521efd3df208fe8a3118b929ebed88db91d5a85d54974742764b7a3709699aad5c3933b9b769bc02f8d27f25ea2df5d73c4607dad720b57e07454f58327e6bf55a833fa5f012a6b7012ef5d0cd4ab7ca9871107ac2a17235d925dd7fd767aa0115d4c5c7b73fe165718895401cf58ec830f95dd4af709064a1c5737b9378775f95c41d078aca3701d50296df1a0af",
        "5d486655b69532b179d825639fe8648cfe468719211f52d35fc9facd8c8572b33e6206aeb819dd96b22f6ade3533f502e1015ca765a236e7ddedf8b5a95bb7f4fa5b1fce132f7ca624a4d4f2adf14e7c31487a35a4685552e2ab149510c4c11a8c6bb5fa21b058b7de597abbe9ddbb178f293ddd07ee15304618b4855696e180e1afae690e15b623941bf719289ea5e72fa597aeb77b133ce409c5cca4e2a5125f1d7e8f085eb5341ba5eab68f80e7382d52a3145dd3c357ddcf2f883e4acf3324a5ab08ad2fb76d22500581d2aa496938ef650f52af5fbb7aae4779f436101a950953cf77433cb6fafa8c0346c716d456e988b4e05861a239bf643860a7340a",
    ]
    # combines shares into secret
    s1 = combine(arr[:3], False)
    print("combines shares 1 length =", len(arr[:3]))
    print("secret:", s1)
    print("secret.length:", len(s1))

    s2 = combine(arr[3:], False)
    print("combines shares 2 length =", len(arr[3:]))
    print("secret:", s2)
    print("secret.length:", len(s2))

    s3 = combine(arr[1:5], False)
    print("combines shares 3 length =", len(arr[1:5]))
    print("secret:", s3)
    print("secret.length:", len(s3))


if __name__ == '__main__':
    # test_dev
    # test_dev()

    # create & combine
    # test1
    test1()

    # # test2
    # test2()

    # # test3
    # test3()

    # # test4
    # test4()
