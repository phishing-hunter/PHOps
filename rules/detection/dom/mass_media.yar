rule nhk_plus {
    meta:
        description = ""
	hashtag = "NHKプラス"
    strings:
        $ = {4e 48 4b e3 83 97 e3 83 a9 e3 82 b9} // NHKプラス
        $ = "Copyright NHK (Japan Broadcasting Corporation)"
    condition:
        all of them
}
