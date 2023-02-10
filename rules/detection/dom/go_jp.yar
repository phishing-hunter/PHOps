rule phishing_go_jp {
    meta:
        description = ""
    strings:
        $ = ".go.jp"
    condition:
        any of them
}

rule NTA_Japan {
    meta:
        description = ""
	official = "@NTA_Japan"
	hashtag = "国税庁"
    strings:
        $ = {e5 9b bd e7 a8 8e e5 ba 81} // 国税庁
        $ = "nta.go.jp"
    condition:
        all of them
}

rule MHLWitter {
    meta:
        description = ""
	official = "@MHLWitter"
	hashtag = "厚生労働省"
    strings:
        $ = {e5 8e 9a e7 94 9f e5 8a b4 e5 83 8d e7 9c 81} //厚生労働省
        $ = "mhlw.go.jp"
    condition:
        all of them
}

rule JMA_kishou {
    meta:
        description = ""
	official = "@JMA_kishou"
	hashtag = "気象庁"
    strings:
        $ = {e6 b0 97 e8 b1 a1 e5 ba 81} // 気象庁
        $ = "jma.go.jp"
    condition:
        all of them
}

rule Kanko_Jpn {
    meta:
        description = ""
	official = "@Kanko_Jpn"
	hashtag = "観光庁"
    strings:
        $ = {e8 a6 b3 e5 85 89 e5 ba 81} // 観光庁
        $ = "mlit.go.jp"
    condition:
        all of them
}

rule MAFF_JAPAN {
    meta:
        description = ""
	official = "@MAFF_JAPAN"
	hashtag = "農林水産省"
    strings:
        $ = {e8 be b2 e6 9e 97 e6 b0 b4 e7 94 a3 e7 9c 81} // 農林水産省
        $ = "maff.go.jp"
    condition:
        all of them
}

rule jpo_NIPPON {
    meta:
        description = ""
	official = "@jpo_NIPPON"
	hashtag = "特許庁"
    strings:
        $ = {e7 89 b9 e8 a8 b1 e5 ba 81} // 特許庁
        $ = "jpo.go.jp"
    condition:
        all of them
}

rule MofaJapan_jp {
    meta:
        description = ""
	official = "@MofaJapan_jp"
	hashtag = "外務省"
    strings:
        $ = {e5 a4 96 e5 8b 99 e7 9c 81} // 外務省
        $ = "mofa.go.jp"
    condition:
        all of them
}

rule MLIT_JAPAN {
    meta:
        description = ""
	official = "@MLIT_JAPAN"
	hashtag = "国土交通省"
    strings:
        $ = {e5 9b bd e5 9c 9f e4 ba a4 e9 80 9a e7 9c 81} // 国土交通省
        $ = "mlit.go.jp"
    condition:
        all of them
}

rule ModJapan_jp {
    meta:
        description = ""
	official = "@ModJapan_jp"
	hashtag = "防衛省"
    strings:
        $ = {e9 98 b2 e8 a1 9b e7 9c 81} // 防衛省
        $ = "mod.go.jp"
    condition:
        all of them
}

rule MIC_JAPAN {
    meta:
        description = ""
	official = "@MIC_JAPAN"
	hashtag = "総務省"
    strings:
        $ = {e7 b7 8f e5 8b 99 e7 9c 81} // 総務省
        $ = "soumu.go.jp"
    condition:
        all of them
}

rule Kankyo_Jpn {
    meta:
        description = ""
	official = "@Kankyo_Jpn"
	hashtag = "環境省"
    strings:
        $ = {e7 92 b0 e5 a2 83 e7 9c 81} // 環境省
        $ = "env.go.jp"
    condition:
        all of them
}

rule mextjapan {
    meta:
        description = ""
	official = "@mextjapan"
	hashtag = "文部科学省"
    strings:
        $ = {e6 96 87 e9 83 a8 e7 a7 91 e5 ad a6 e7 9c 81} // 文部科学省
        $ = "mext.go.jp"
    condition:
        all of them
}

rule MOF_Japan {
    meta:
        description = ""
	official = "@MOF_Japan"
	hashtag = "財務省"
    strings:
        $ = {e8 b2 a1 e5 8b 99 e7 9c 81} // 財務省
        $ = "mof.go.jp"
    condition:
        all of them
}

rule meti_NIPPON {
    meta:
        description = ""
	official = "@meti_NIPPON"
	hashtag = "経済産業省"
    strings:
        $ = {e7 b5 8c e6 b8 88 e7 94 a3 e6 a5 ad e7 9c 81} // 経済産業省
        $ = "meti.go.jp"
    condition:
        all of them
}

rule MOJ_HOUMU {
    meta:
        description = ""
	official = "@MOJ_HOUMU"
	hashtag = "法務省"
    strings:
        $ = {e6 b3 95 e5 8b 99 e7 9c 81} // 法務省
        $ = "moj.go.jp"
    condition:
        all of them
}

rule MOJ_PSIA {
    meta:
        description = ""
	official = "@MOJ_PSIA"
	hashtag = "公安調査庁"
    strings:
        $ = {e5 85 ac e5 ae 89 e8 aa bf e6 9f bb e5 ba 81} // 公安調査庁
        $ = "moj.go.jp/psia"
    condition:
        all of them
}

rule NPA_KOHO {
    meta:
        description = ""
        official = "@NPA_KOHO"
	hashtag = "警察庁"
    strings:
        $ = {e8 ad a6 e5 af 9f e5 ba 81} // 警察庁
        $ = "npa.go.jp"
    condition:
        all of them
}

rule fsa_JAPAN {
    meta:
        description = ""
	official = "@fsa_JAPAN"
	hashtag = "金融庁"
    strings:
        $ = {e9 87 91 e8 9e 8d e5 ba 81} // 金融庁
        $ = "fsa.go.jp"
    condition:
        all of them
}

rule PPC_JPN {
    meta:
        description = ""
	official = "@PPC_JPN"
	hashtag = "個人情報保護委員会"
    strings:
        $ = {e5 80 8b e4 ba ba e6 83 85 e5 a0 b1 e4 bf 9d e8 ad b7 e5 a7 94 e5 93 a1 e4 bc 9a} // 個人情報保護委員会
        $ = "ppc.go.jp"
    condition:
        all of them
}

rule gensiryokukisei {
    meta:
        description = ""
	official = "@gensiryokukisei"
	hashtag = "原子力規制委員会"
    strings:
        $ = {e5 8e 9f e5 ad 90 e5 8a 9b e8 a6 8f e5 88 b6 e5 a7 94 e5 93 a1 e4 bc 9a} // 原子力規制委員会
        $ = "nra.go.jp"
    condition:
        all of them
}

rule cao_japan {
    meta:
        description = ""
	official = "@cao_japan"
	hashtag = "内閣府"
    strings:
        $ = {e5 86 85 e9 96 a3 e5 ba 9c} // 内閣府
        $ = "cao.go.jp"
    condition:
        all of them
}

rule Naikakukanbo {
    meta:
        description = ""
	official = "@Naikakukanbo"
	hashtag = "内閣官房"
    strings:
        $ = {e5 86 85 e9 96 a3 e5 ae 98 e6 88 bf} // 内閣官房
        $ = "cas.go.jp"
    condition:
        all of them
}

rule kantei {
    meta:
        description = ""
	official = "@kantei"
	hashtag = "首相官邸"
    strings:
        $ = {e9 a6 96 e7 9b b8 e5 ae 98 e9 82 b8} // 首相官邸
        $ = "kantei.go.jp"
    condition:
        all of them
}
