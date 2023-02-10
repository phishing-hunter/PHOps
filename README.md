# Phishing Hunging Operations (PHOps) :rocket:

![PHOps](https://i.imgur.com/6JUrywC.png)

:guardsman: Repository for automating Phishing Hunting Operations (PHOps)  
If you need to modify scoring rules, etc., please Pull Request. 📈  
The repository is updated regularly on a daily basis, but if you require more timely notification of information, please create a user account on [Discord](https://discord.gg/c2WWJDpnAw) :robot: or [here](http://phishing-hunter.com/login). 📩  

We believe that in order to combat the latest threats, such as scattershot types, it is necessary to keep the configuration values open and keep the patterns up-to-date.  
The scoring algorithm is also available here. If you would like to suggest modifications to the algorithm, please send a Pull Request to this [repository](https://github.com/phishing-hunter/cert-hunter).  

## Hunting Archive
Certificate Transparency Logs and Phishing Kit collected by [phishing-hunter](http://phishing-hunter.com/).  

* [Certificate Transparency Logs](https://drive.google.com/drive/folders/1cUyCmCEl865rnZXjIywa0P9OcwwNm5Ac?usp=sharing)🕵️  
* [Phishing Kit](https://drive.google.com/drive/folders/1NgiIRjswwYlk9u8z1ONdh2AtTG2L0GL-?usp=sharing) :toolbox:
* [Discord](https://discord.gg/c2WWJDpnAw) :robot:

## How to Test
* detection target score: 150
* max detection domains par day: 500
```
$ docker run --rm -it \
    -v $PWD:/work \
	-w /work \
	phishinghunter/cert-hunter:20230125 \
	/app/checker.py suspicious.yaml -f /csv/target.csv -m 500 -s 150
```
Yara rule test
```bash
$ yara rules/index_test.yar /test.zip
```

## Reference
* [Malware Analysis Operations（MAOps）の自動化](https://blogs.jpcert.or.jp/ja/2023/01/cloud_malware_analysis.html)
