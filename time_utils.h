#include <stdexcept>
#include <ctime>


namespace time_utils {

    /** Determine whether the given year is a leap year.
     *
     *  This assumes the standard Gregorian (=modern western) calendar for all
     *  years; note that this is incorrect for historical years and for local
     *  year representations in certain countries.
     */
    constexpr bool is_leap_year(int year) noexcept
    {
        // Years divisible by 4 are leap years, except when divisible by 100
        // and not by 400.
        return year % 4 == 0 && !(year % 100 == 0 && year % 400 != 0);
    }

    /** Computes the number of days in February in the given year.
     *
     *  This depends on whether the year is a leap year.
     */
    constexpr int days_in_february(int year) noexcept
    {
        if (is_leap_year(year)) {
            return 29;
        } else {
            return 28;
        }
    }

    /** Computes the number of days in the given month.
     *
     *  This depends on whether the year is a leap year. Note that the month is
     *  1-based.
     *
     *  Please note: If the month is out of range, this is undefined behavior.
     *
     *  @pre 1 <= month <= 12
     *  @param year      The year in which this month falls.
     *  @param month     The month of which the number of days is requested;
     *                   january is 1, febuary is 2, ..., december is 12.
     */
    constexpr int days_in_month(int year, int month) noexcept
    {
        constexpr const int days_in_month[12] = {
            31, -1, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
        };

        if (month == 2) {
            return days_in_february(year);
        } else {
            return days_in_month[month - 1];
        }
    }

    /** Computes the number of days in the given year.
     *
     *  This depends on whether the year is a leap year.
     *
     *  @param year      The year of which the number of days is requested.
     */
    constexpr int days_in_year(int year) noexcept
    {
        if (is_leap_year(year)) {
            return 366;
        } else {
            return 365;
        }
    }

    /** Computes the number of days in all months in the year before the
     *  specified month.
     *
     *  For example, days_in_year_before_month(2001, 3) == 31 + 28 == 59, since
     *  before month 3 (march) there are only the months january and february,
     *  and in 2001 these have 31 and 28 days, respectively.
     *
     *  This function runs in constant time.
     *
     *  Please note: If the month is out of range, this is undefined behavior.
     *
     *  @pre 1 <= month <= 12
     *  @param year      The year in which this month falls.
     *  @param month     The month of which the preceding day count is asked;
     *                   january is 1, febuary is 2, ..., december is 12.
     *  @return The number of days before the start of the given month in the
     *          given year.
     */
    constexpr int days_in_year_before_month(int year, int month) noexcept
    {
        // The number of days before some month, assuming it is NOT a leap year.
        constexpr const int days_before_nonleap[12] = {
            0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
        };

        // If it is a leap year and february is before the given month
        if (is_leap_year(year) && 2 < month) {
            // Compensate for the leap day
            return days_before_nonleap[month - 1] + 1;
        } else {
            // No need to compensate: not a leap year
            return days_before_nonleap[month - 1];
        }
    }

    /** Computes the number of days since 1970-01-01 00:00:00 until the start
     *  of the given year.
     *
     *  This function runs in constant time.
     *
     *  @pre year >= 1970
     */
    constexpr int days_since_unix_epoch(int year)
    {
        if (year < 1970) {
            // This will call std::terminate, but we'll have to make do.
            throw std::out_of_range("Year less than unix epoch in days_since_unix_epoch");
        }

        if (year < 2000) {
            // Every fourth year is a leap year, starting with 1972.
            return (year - 1970) * 365 + (year - 1970 + 1) / 4;
        } else {
            // First compute the number of days before the year 2000
            int days_before_2000 = (2000 - 1970) * 365 + (2000 - 1970 + 1) / 4;

            // Then compute the number of days after 2000, ignoring special cases
            int days_from_2000 = (year - 2000) * 365 + (year - 2000 + 3) / 4;

            // Every hundredth year is _not_ a leap year
            days_from_2000 -= (year - 2000 + 99) / 100;

            // But every four-hundredth year _is_ a leap year
            days_from_2000 += (year - 2000 + 399) / 400;

            return days_before_2000 + days_from_2000;
        }
    }

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
    std::time_t tm_to_utc_unix_timestamp(const std::tm &time);


    /** Some compile-time unit tests for the above.
     */
    namespace unit_tests {
        // Define some useful constants
        constexpr const int a_nonleap_year = 2001;
        static_assert(!is_leap_year(a_nonleap_year));

        constexpr const int a_leap_year = 2004;
        static_assert(is_leap_year(a_leap_year));

        // Check whether the leap year calculation is correct
        static_assert(is_leap_year(2000));
        static_assert(!is_leap_year(2100));
        static_assert(!is_leap_year(2200));
        static_assert(!is_leap_year(2300));
        static_assert(is_leap_year(2400));

        // Check whether days_in_year_before_month is correct
        template <int year, int month>
        struct days_before_month_correct {
            static_assert(days_in_year_before_month(year, month) == days_in_year_before_month(year, month - 1) + days_in_month(year, month - 1));
            static constexpr const bool correct = days_before_month_correct<year, month - 1>::correct;
        };

        template <int year>
        struct days_before_month_correct<year, 1> {
            static_assert(days_in_year_before_month(year, 1) == 0);
            static constexpr const bool correct = true;
        };

        static_assert(days_before_month_correct<a_nonleap_year, 12>::correct);
        static_assert(days_before_month_correct<a_leap_year, 12>::correct);
    }
}
