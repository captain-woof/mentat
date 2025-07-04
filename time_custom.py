import time
import random

def sleepRandom(llimit = 1.5, ulimit = 5):
    timeToSleepSecs = llimit + ((ulimit - llimit) * random.random())
    time.sleep(timeToSleepSecs)