import datetime
import random
import time


def generateString(minstrlen=11, maxstrlen=200):
    length = random.randint(minstrlen, maxstrlen)
    return "".join([chr(random.randint(ord(' '), ord('~'))) for _ in range(length)])

def generateName():
    return generateString()

def generateEmail():
    return generateString()

def generateDate(mindate_unix=631152000, maxdate_unix=2**32):
    # Python's date functions don't handle dates past 9999 properly,
    # but this is a sensible default range
    timestamp = random.randint(mindate_unix, maxdate_unix)
    date = datetime.datetime.fromtimestamp(timestamp)

    return date.isoformat(sep=' ')

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
    date_extension = random.randint(1, 1825)
    date_key_creation = generateDate(maxdate_unix=now)
    date_creation = generateDate(maxdate_unix=now)
    date_expiration = generateDate(mindate_unix=now, maxdate_unix=2**32 - date_extension * 60 * 60 * 24)
    # the key creation date has to be before the signature creation date
    date_key_creation, date_creation = sorted([date_key_creation, date_creation])

    return {
        "name": generateName(),
        "email": generateEmail(),
        "creation": date_creation,
        "expiration": date_expiration,
        "dice": generateDice(),
        "key": generateSymmetricKey(),
        "key_creation": date_key_creation,
        "extension_period": str(date_extension),
    }
