rule c2panel {
    meta:
        description = ""
    strings:
        $ = "HTTrack Website Copier/3.x" // mars
        $ = {4c 75 6d 6d 61 20 7c 20 d0 92 d1 85 d0 be d0 b4} // Lumma | Вход 
        $ = "Welcome back! Please signin to continue." // oski
        $ = "Gomorrah " // Gomorrah
        $ = "ERBIUM" // Erbium
        $ = "BlackNET" // blacknet
        $ = "Kurisu Login" //vertex
        $ = "Collector Stealer panel" // collector
    condition:
        any of them
}
