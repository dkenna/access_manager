import subprocess
import sys

keys = subprocess.run(['/usr/local/MacGPG2/bin/gpg2','--list-keys'],stdout=subprocess.PIPE)
out = str(keys.stdout)
print(type(out))
#get non-empty lines
lines = [ x.strip() for x in out.split("\\n") if x.strip() and x.startswith("uid")]
for i in lines:
    toks = i.split(" ")
    print (toks[9:])
    #uid = i.split("\t")[0]
    #print(uid)
sys.exit(1)

