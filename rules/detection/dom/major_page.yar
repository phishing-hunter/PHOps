rule SMBC {
    meta:
        description = ""
	official = "@smbc_midosuke"
	hashtag = "三井住友銀行"
    strings:
        $ = {53 4d 42 43 e3 82 b0 e3 83 ab e3 83 bc e3 83 97} // SMBCグループ
        $ = {e4 b8 89 e4 ba 95 e4 bd 8f e5 8f 8b} // 三井住友
    condition:
        any of them
}

rule MUFG {
    meta:
        description = ""
	official = "@mufgbk_official"
	hashtag = "三菱UFJ"
    strings:
        $ = {e4 b8 89 e8 8f b1 55 46 4a} // 三菱UFJ
        $ = {4d 55 46 47 e3 82 ab e3 83 bc e3 83 89} // MUFGカード
    condition:
        any of them
}

rule AMEX {
    meta:
        description = ""
	official = "@AmexJP"
	hashtag = "アメックス"
    strings:
        $ = {e3 82 a2 e3 83 a1 e3 83 aa e3 82 ab e3 83 b3 e3 83 bb e3 82 a8 e3 82 ad e3 82 b9 e3 83 97 e3 83 ac e3 82 b9} // アメリカン・エキスプレス
        $ = {e3 82 a2 e3 83 a1 e3 83 83 e3 82 af e3 82 b9} // アメックス
    condition:
        any of them
}

rule JACCS {
    meta:
        description = ""
	hashtag = "ジャックス・インターコムクラブ"
	official = "@jaccsmiratane"
    strings:
        $ = {e3 82 b8 e3 83 a3 e3 83 83 e3 82 af e3 82 b9} // ジャックス
        $ = {e3 82 a4 e3 83 b3 e3 82 bf e3 83 bc e3 82 b3 e3 83 a0 e3 82 af e3 83 a9 e3 83 96} // インターコムクラブ
    condition:
        all of them
}

rule viewcard {
    meta:
        description = ""
        hashtag = "ビューカード"
        official = "@viewcardJP"
    strings:
        $ = "VIEW's NET"
        $ = {e3 83 93 e3 83 a5 e3 83 bc e3 82 ab e3 83 bc e3 83 89} // ビューカード
    condition:
        any of them
}

rule creditcard_page {
    meta:
        description = ""
        hashtag = "クレジットカード"
    strings:
        $ = {e3 82 af e3 83 ac e3 82 b8 e3 83 83 e3 83 88 e3 82 ab e3 83 bc e3 83 89} // クレジットカード
        $ = {e3 83 ad e3 82 b0 e3 82 a4 e3 83 b3} // ログイン
    condition:
        all of them
}

rule jr_east {
    meta:
        description = ""
	official = "@Ekinet_jrnets"
        hashtag = "えきねっと"
    strings:
        $ = {e3 81 88 e3 81 8d e3 81 ad e3 81 a3 e3 81 a8} // えきねっと
        $ = {e3 83 ad e3 82 b0 e3 82 a4 e3 83 b3} // ログイン
    condition:
        all of them
}

rule AmazonJapan {
    meta:
        description = ""
        hashtag = "Amazonフィッシングサイト"
	official = "@AmazonJP"
    strings:
        $ = {41 6d 61 7a 6f 6e e3 82 b5 e3 82 a4 e3 83 b3 e3 82 a4 e3 83 b3} // Amazonサインイン
    condition:
        any of them
}

rule au_ID {
    meta:
        description = ""
        hashtag = "au ID"
	official = "@au_official"
    strings:
        $ = {61 75 20 49 44 e3 83 ad e3 82 b0 e3 82 a4 e3 83 b3} // au IDログイン
        $ = {61 75 20 49 44 e3 81 a7 e3 83 ad e3 82 b0 e3 82 a4 e3 83 b3} // au IDでログイン
    condition:
        any of them
}

rule rakuten {
    meta:
        description = ""
        hashtag = "楽天"
	official = "@RakutenJP"
    strings:
        $ = {e6 a5 bd e5 a4 a9 e4 bc 9a e5 93 a1} // 楽天会員
        $ = {e3 80 90 e6 a5 bd e5 a4 a9 e3 80 91 e3 83 ad e3 82 b0 e3 82 a4 e3 83 b3} // 【楽天】ログイン
    condition:
        any of them
}

rule epos_card {
    meta:
        description = ""
        hashtag = "エポスカード"
	official = "@epos_card"
    strings:
        $ = {e3 82 a8 e3 83 9d e3 82 b9 e3 82 ab e3 83 bc e3 83 89} // エポスカード
        $ = {e3 82 a8 e3 83 9d e3 82 b9 4e 65 74} // エポスNet
    condition:
        any of them
}
