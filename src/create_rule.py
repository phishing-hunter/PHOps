import csv
import requests

url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
response = requests.get(url)

with open("/tmp/sslblacklist.csv", "wb") as file:
    file.write(response.content)

rules = {}
with open("/tmp/sslblacklist.csv") as f:
    reader = csv.reader(filter(lambda row: row[0]!='#', f))
    for ts, finger, tag in reader:
        tag = tag.replace("&", "n").replace(" ", "_").replace('.', '_').replace('-', '_')
        rules[tag] = rules.get(tag, [])
        rules[tag].append(finger)

with open("./rules/detection/ssl/sslblacklist.yar", "w") as f:
    for name in rules.keys():
        fingers = rules[name]
        f.write("rule " + name + "\n")
        f.write("{\n")
        f.write("\tstrings:\n")
        for finger in fingers:
            f.write(f'\t\t$ = "{finger}"\n')
        f.write("\tcondition:\n")
        f.write("\t\tany of them\n")
        f.write("}\n")

