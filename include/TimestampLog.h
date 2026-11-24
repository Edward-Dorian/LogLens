#pragma once

#include <compare>
#include <optional>
#include <ostream>
#include <string_view>

class TimestampLog {
private:
    int an;
    int luna;
    int zi;
    int ora;
    int minut;
    int secunda;

    [[nodiscard]] long long laSecundeEpoch() const;

public:
    TimestampLog(int an_, int luna_, int zi_, int ora_, int minut_, int secunda_);

    // Returneaza diferenta in secunde (this - other).
    [[nodiscard]] long long diferentaSecunde(const TimestampLog& other) const;

    [[nodiscard]] bool operator==(const TimestampLog& other) const = default;
    [[nodiscard]] auto operator<=>(const TimestampLog& other) const = default;

    friend std::ostream& operator<<(std::ostream& os, const TimestampLog& ts);
};

[[nodiscard]] std::optional<TimestampLog> parseazaTimestampLog(std::string_view text);
