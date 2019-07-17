import random

from date_utils import *


# Class hierarchy for randomly generating various kinds of data for input into
# the program
class Generate:
    def generate():
        raise NotImplementedError()

class GenerateString(Generate):
    def generate():
        length = random.randint(1, 200)
        return "".join([chr(random.randint(ord(' '), ord('~'))) for _ in range(length)])

class GenerateName(GenerateString):
    pass

class GenerateEmail(GenerateString):
    pass

class GenerateDate(Generate):
    def generate():
        while True:
            year = random.randint(1990, 2100)
            month = random.randint(1, 12)
            day = random.randint(1, days_in_month(year, month))
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            string = "{:04}-{:02}-{:02} {:02}:{:02}:{:02}".format(year, month, day, hour, minute, second)
            if date_to_unix(string) >= 1511740800:  # TODO: Change to variable date
                return string

class GenerateDatePair(Generate):
    def generate():
        while True:
            values = [GenerateDate.generate(), GenerateDate.generate()]
            #  if values[0] == values[1]:
            #      continue
            values.sort()
            return tuple(values)

class GenerateDie(Generate):
    def generate():
        return random.randint(1, 6)

class GenerateDice(Generate):
    def generate():
        length = 100 if random.randint(0, 1) == 0 else random.randint(100, 1000)
        return "".join(str(GenerateDie.generate()) for _ in range(length))

class GenerateSymmetricKey(GenerateString):
    pass

class GenerateInput():
    def generate():
        datepair = GenerateDatePair.generate()
        return {
            "name": GenerateName.generate(),
            "email": GenerateEmail.generate(),
            "creation": datepair[0],
            "expiration": datepair[1],
            "dice": GenerateDice.generate(),
            "key": GenerateSymmetricKey.generate(),
            "context": GenerateString.generate(),
            "key_creation": "2017-11-27 00:00:00",
        }
