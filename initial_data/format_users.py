import subprocess
from django.contrib.auth.models import User


#gpg_users = ['KwakiutlBob','fabfivefred','donkey2','zunidog','drearnhardt','deepmeds','Roxtar','OxyMonster','Maquenna','Highway','lucid','lllMMMlll','DoctorD','Foreigner','Tom','Highclub','DrogMann','amsterdam','Justme','DutchFactory','25-7-DREAM']
lines = [ x.strip() for x in open("users.txt").read().split("\n") if x.strip() ]
gpg_users = {}
for i in lines: 
    toks = i.split("|")
    gpg_users[toks[0]] = toks[1] 
for i in gpg_users.keys():
    public_key = subprocess.run(["/usr/local/MacGPG2/bin/gpg2","--export","-a",i],stdout=subprocess.PIPE)
    public_key = public_key.stdout
    print(i)
    public_key = "".join( chr(x) for x in public_key)
    user = User()
    user.username = i
    user.email = gpg_users[i]
    user.password = "password1"
    user.save()
    user.profile.public_key = public_key
    user.save()
    #print(public_key)
