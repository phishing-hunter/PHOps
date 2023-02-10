rule jalan {
    meta:
        description = ""
	hashtag = "ホテル予約サイト"
    strings:
        $ = {e3 83 9b e3 83 86 e3 83 ab} // ホテル
        $ = {e4 ba 88 e7 b4 84} // 予約
        $ = {e3 81 98 e3 82 83 e3 82 89 e3 82 93} // じゃらん
        $ = {e3 83 9e e3 82 a4 e3 83 9a e3 83 bc e3 82 b8} // マイページ
    condition:
        all of them
}
