import random

import time
from date_utils import *


def generateString(**kwargs):
    length = random.randint(kwargs.get("minstrlen", 1), kwargs.get("maxstrlen", 200))
    return "".join([chr(random.randint(ord(' '), ord('~'))) for _ in range(length)])

def generateName():
    return generateString()

def generateEmail():
    return generateString()

def generateDate(**kwargs):
    while True:
        year = random.randint(1990, 2100)
        month = random.randint(1, 12)
        day = random.randint(1, days_in_month(year, month))
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        string = "{:04}-{:02}-{:02} {:02}:{:02}:{:02}".format(year, month, day, hour, minute, second)
        if kwargs.get("mindate_unix", 0) <= date_to_unix(string) <= kwargs.get("maxdate_unix", 2 ** 63):
            return string

def generateDie():
    return random.randint(1, 6)

def generateDice():
    length = 100 if random.randint(0, 1) == 0 else random.randint(100, 1000)
    return "".join(str(generateDie()) for _ in range(length))

def generateSymmetricKey():
    return generateString()

def generateInput():
    # generate some dates in the right range
    now = int(time.time())
    date_key_creation = generateDate(maxdate_unix = now)
    date_creation = generateDate(maxdate_unix = now)
    date_expiration = generateDate(mindate_unix = now)
    # the key creation date has to be before the signature creation date
    date_key_creation, date_creation = sorted([date_key_creation, date_creation])

    return {
        "name": generateName(),
        "email": generateEmail(),
        "creation": date_creation,
        "expiration": date_expiration,
        "dice": generateDice(),
        "key": generateSymmetricKey(),
        "context": generateString(minstrlen = 8, maxstrlen = 8),
        "key_creation": date_key_creation
    }
