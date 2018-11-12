from django.shortcuts import render
import time

class TimestampGenerator:
    def __init__(self):
        return time.time()

class TimestampSigner:
    def __init__(self,signer):
        self.signer = signer


