rule fake_anti_virus {
    meta:
        url = "https://www.ipa.go.jp/security/anshin/mgdayori20221025.html"
        description = "偽セキュリティ警告から自動継続課金アプリのインストールへ誘導"
        hashtag = "偽セキュリティ警告"
    strings:
        $ = {e3 82 a6 e3 82 a4 e3 83 ab e3 82 b9 e3 81 8c} // ウイルスが
        $ = {e6 a4 9c e5 87 ba e3 81 95 e3 82 8c e3 81 be e3 81 97 e3 81 9f} // 検出されました
    condition:
        all of them
}

rule anti_virus {
    meta:
        hashtag = "偽アンチウイルス"
    strings:
        $ = {e3 82 a2 e3 83 b3 e3 83 81 e3 82 a6 e3 82 a4 e3 83 ab e3 82 b9} // アンチウイルス
	$ = {e5 85 ac e5 bc 8f} // 公式
    condition:
        all of them
}
