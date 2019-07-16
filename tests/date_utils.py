import datetime


def is_leap_year(year):
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)

def days_in_month(year, month):
    if month == 2:
        if is_leap_year(year): return 29
        else: return 28
    return [31, None, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]

# Convert a string date representation to a UNIX timestamp
def date_to_unix(string):
    return int(
        # parse the string into a datetime object
        datetime.datetime.strptime(string, "%Y-%m-%d %H:%M:%S")
        # tell it to consider itself a UTC time
            .replace(tzinfo = datetime.timezone.utc)
        # obtain the timestamp
            .timestamp()
    )
