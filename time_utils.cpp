#include "time_utils.h"


/** Convert a splitted-out time point representation to a UNIX timestamp.
 *
 *  This function only exists because there is no standard function
 *  corresponding to std::gmtime like std::mktime corresponsds to
 *  std::localtime.
 *
 *  The following fields of 'time' are inspected, with their valid ranges:
 *  - tm_sec [0,60]
 *  - tm_min [0,59]
 *  - tm_hour [0,23]
 *  - tm_mday [1,31]
 *  - tm_mon [0,11]
 *  - tm_year >= 70 (tm_year counts the years since 1900; a UNIX timestamp
 *                   requires that the year be >= 1970.)
 *  The other fields (tm_wday, tm_yday and tm_isdst) are ignored.
 *
 *  NOTE: The inspected fields MUST be in their respective ranges. This is
 *        unlike the standard std::mktime function, which allows fields to
 *        be out-of-range.
 *
 *  @param time      The time representation to convert
 *  @return The UNIX timestamp corresponding to the input when interpreted as a
 *          time point in UTC.
 *  @throws std::out_of_range  If any field is outside its range.
 */
std::time_t time_utils::tm_to_utc_unix_timestamp(const std::tm &time)
{
    if (time.tm_sec  <  0 || time.tm_sec  >= 61) { throw std::out_of_range{ "Seconds out of range"        }; }
    if (time.tm_min  <  0 || time.tm_min  >= 60) { throw std::out_of_range{ "Minutes out of range"        }; }
    if (time.tm_hour <  0 || time.tm_hour >= 24) { throw std::out_of_range{ "Hours out of range"          }; }
    if (time.tm_mday <  1 || time.tm_mday >= 32) { throw std::out_of_range{ "Day-of-month out of range"   }; }
    if (time.tm_mon  <  0 || time.tm_mon  >= 12) { throw std::out_of_range{ "Month out of range"          }; }
    if (time.tm_year < 70                      ) { throw std::out_of_range{ "Year out of range"           }; }

    std::time_t second_in_day = 3600 * time.tm_hour + 60 * time.tm_min + time.tm_sec;

    std::time_t day_in_year = days_in_year_before_month(1900 + time.tm_year, time.tm_mon + 1) + (time.tm_mday - 1);

    std::time_t second_in_year = 24 * 3600 * day_in_year + second_in_day;

    std::time_t seconds_before_year = 24 * 3600 * static_cast<std::time_t>(days_since_unix_epoch(1900 + time.tm_year));

    return seconds_before_year + second_in_year;
}
