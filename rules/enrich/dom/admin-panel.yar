rule admin_panel {
	meta:
		description = "admin panel"
		author = "tatsui"
	strings:
		$s1 = " Proxmox Virtual Environment"
		$s2 = " Synology NAS"
		$s3 = "cPanel Login"
	condition:
		any of them
}


