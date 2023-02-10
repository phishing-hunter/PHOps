rule hello_world_page {
	meta:
		description = "hello world page"
		author = "tatsui"
	strings:
		$s1 = "helloworld" wide ascii
		$s2 = "hello world" wide ascii
		$s3 = "HelloWorld" wide ascii
		$s4 = "Hello World" wide ascii
	condition:
		any of them
}
