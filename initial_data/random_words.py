import random
import os

def esc(text):
    chars = '''\<>#%{}|^~[]:;/?@&'"'''
    for c in chars:
        text = text.replace(c, "-")
    return text.strip('-').strip(".") # strip trailing


def gen_passphrase():
    r = random.SystemRandom()
    words = [ x for x in open("initial_data/words.txt").read().split("\n") ]
    seed = []

    for i in range(25):
        rand_j =  r.randrange(len(words))
        word = esc(words[rand_j].lower())
        seed.append(word)
    return " ".join(seed)
    
if __name__ == "__main__":
    print(gen_passphrase())
