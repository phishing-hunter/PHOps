rule index_of {
	meta:
		description = "index of page"
		author = "tatsui"
	strings:
		$s1 = "Index of /" wide ascii
	condition:
		any of them
}

rule index_of_zip {
	meta:
		description = "index of page developer setting"
		author = "tatsui"
	strings:
		$s1 = "Index of /" wide ascii
		$s2 = ".zip" wide ascii
	condition:
		all of them
}

rule index_of_conf {
	meta:
		description = "index of page developer setting"
		author = "tatsui"
	strings:
		$s1 = "Index of /" wide ascii
		$s2 = ".conf" wide ascii
	condition:
		all of them
}

rule index_of_sql {
	meta:
		description = "index of page developer setting"
		author = "tatsui"
	strings:
		$s1 = "Index of /" wide ascii
		$s2 = ".sql" wide ascii
	condition:
		all of them
}

rule index_of_csv {
	meta:
		description = "index of page developer setting"
		author = "tatsui"
	strings:
		$s1 = "Index of /" wide ascii
		$s2 = ".csv" wide ascii
	condition:
		all of them
}


rule index_of_xls {
	meta:
		description = "index of page developer setting"
		author = "tatsui"
	strings:
		$s1 = "Index of /" wide ascii
		$s2 = ".xls" wide ascii
	condition:
		all of them
}

rule index_of_xlsx {
	meta:
		description = "index of page developer setting"
		author = "tatsui"
	strings:
		$s1 = "Index of /" wide ascii
		$s2 = ".xlsx" wide ascii
	condition:
		all of them
}
