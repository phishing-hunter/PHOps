rule empty_page {
	meta:
		description = "empty page"
		author = "tatsui"
	strings:
		$s1 = "<body></body>"
		$s2 = "<html><head></head><body>"
	condition:
		any of them
}


