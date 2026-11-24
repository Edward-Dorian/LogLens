#include "TimestampLog.h"

#include <chrono>
#include <iomanip>
#include <sstream>

namespace {
constexpr std::size_t kLungimeTimestamp = 19;
constexpr int kLunaMin = 1;
constexpr int kLunaMax = 12;
constexpr int kZiMin = 1;
constexpr int kZiMax = 31;
constexpr int kOraMax = 23;
constexpr int kMinutMax = 59;
constexpr int kSecundaMax = 59;

bool parseazaCifre(std::string_view segment, int& rezultat) {
    if (segment.empty()) {
        return false;
    }
    int valoare{0};
    for (const char ch : segment) {
        if (ch < '0' || ch > '9') {
            return false;
        }
        valoare = valoare * 10 + (ch - '0');
    }
    rezultat = valoare;
    return true;
}
} // namespace

TimestampLog::TimestampLog(int an_, int luna_, int zi_, int ora_, int minut_, int secunda_)
    : an{an_},
      luna{luna_},
      zi{zi_},
      ora{ora_},
      minut{minut_},
      secunda{secunda_} {}

std::optional<TimestampLog> parseazaTimestampLog(std::string_view text) {
    if (text.size() != kLungimeTimestamp ||
        text[4] != '-' || text[7] != '-' || text[10] != ' ' ||
        text[13] != ':' || text[16] != ':') {
        return std::nullopt;
    }

    int anVal{0};
    int lunaVal{0};
    int ziVal{0};
    int oraVal{0};
    int minutVal{0};
    int secundaVal{0};

    if (!parseazaCifre(text.substr(0, 4), anVal) ||
        !parseazaCifre(text.substr(5, 2), lunaVal) ||
        !parseazaCifre(text.substr(8, 2), ziVal) ||
        !parseazaCifre(text.substr(11, 2), oraVal) ||
        !parseazaCifre(text.substr(14, 2), minutVal) ||
        !parseazaCifre(text.substr(17, 2), secundaVal)) {
        return std::nullopt;
    }

    if (lunaVal < kLunaMin || lunaVal > kLunaMax ||
        ziVal < kZiMin || ziVal > kZiMax ||
        oraVal < 0 || oraVal > kOraMax ||
        minutVal < 0 || minutVal > kMinutMax ||
        secundaVal < 0 || secundaVal > kSecundaMax) {
        return std::nullopt;
    }

    const std::chrono::year_month_day ymd{
        std::chrono::year{anVal},
        std::chrono::month{static_cast<unsigned>(lunaVal)},
        std::chrono::day{static_cast<unsigned>(ziVal)}
    };
    if (!ymd.ok()) {
        return std::nullopt;
    }

    return TimestampLog{anVal, lunaVal, ziVal, oraVal, minutVal, secundaVal};
}

long long TimestampLog::laSecundeEpoch() const {
    const std::chrono::year_month_day ymd{
        std::chrono::year{an},
        std::chrono::month{static_cast<unsigned>(luna)},
        std::chrono::day{static_cast<unsigned>(zi)}
    };
    const auto moment = std::chrono::sys_days{ymd} +
                        std::chrono::hours{ora} +
                        std::chrono::minutes{minut} +
                        std::chrono::seconds{secunda};
    return static_cast<long long>(
        std::chrono::duration_cast<std::chrono::seconds>(moment.time_since_epoch()).count());
}

long long TimestampLog::diferentaSecunde(const TimestampLog& other) const {
    return laSecundeEpoch() - other.laSecundeEpoch();
}

std::ostream& operator<<(std::ostream& os, const TimestampLog& ts) {
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(4) << ts.an << '-'
        << std::setw(2) << ts.luna << '-'
        << std::setw(2) << ts.zi << ' '
        << std::setw(2) << ts.ora << ':'
        << std::setw(2) << ts.minut << ':'
        << std::setw(2) << ts.secunda;
    os << oss.str();
    return os;
}
