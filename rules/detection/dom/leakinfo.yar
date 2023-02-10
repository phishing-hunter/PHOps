rule LeakInfo {
    meta:
        description = "情報漏洩"
    strings:
        $ = {e7 a4 be e5 86 85 e3 83 9d e3 83 bc e3 82 bf e3 83 ab} // 社内ポータル
        $ = {e7 a4 be e5 a4 96 e7 a7 98} // 社外秘
    condition:
        any of them
}
