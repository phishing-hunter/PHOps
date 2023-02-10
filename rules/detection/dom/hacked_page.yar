rule hacked_by {
    meta:
        description = "hacked by page"
    strings:
        $ = /hacked by/is
    condition:
        any of them
}
