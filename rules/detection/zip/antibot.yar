import "zip"

rule PK_Generic_Killbot
{
    strings:
        $zip_file = { 50 4b 03 04 }
        $ = /killbot.php/is
        $ = /killbot.ini/is
        $ = /blocker.php/is
        $ = /blocker.ini/is
        $ = /antibot.php/is
        $ = /antibot.ini/is

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        2 of them or
        zip.has_string("index.php", "antibot") > 0 or
        zip.has_string("index.php", "killbot") > 0 or
        zip.has_string("settings.json", "antibot") > 0 or
        zip.has_string("settings.json", "killbot") > 0 or
        zip.has_string("config.json", "antibot") > 0 or
        zip.has_string("config.json", "killbot") > 0 or
        zip.has_string("config.php", "antibot") > 0 or
        zip.has_string("config.php", "killbot") > 0
}
