#include "internal/TextUtils.h"

#include <cctype>

namespace loglens::internal {

std::string transformaInLitereMici(std::string_view text) {
    std::string rezultat;
    rezultat.reserve(text.size());
    for (const char ch : text) {
        rezultat.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return rezultat;
}

std::string eliminaSpatiiMargini(std::string_view text) {
    const std::size_t inceput = text.find_first_not_of(" \t\r\n");
    if (inceput == std::string_view::npos) {
        return "";
    }
    const std::size_t sfarsit = text.find_last_not_of(" \t\r\n");
    return std::string{text.substr(inceput, sfarsit - inceput + 1)};
}

std::string curataSfarsitLinie(std::string_view linie) {
    if (!linie.empty() && linie.back() == '\r') {
        return std::string{linie.substr(0, linie.size() - 1)};
    }
    return std::string{linie};
}

std::string scapaCaractereJson(std::string_view text) {
    std::string rezultat;
    rezultat.reserve(text.size());
    for (const char ch : text) {
        switch (ch) {
            case '"':
                rezultat += "\\\"";
                break;
            case '\\':
                rezultat += "\\\\";
                break;
            case '\n':
                rezultat += "\\n";
                break;
            case '\r':
                rezultat += "\\r";
                break;
            case '\t':
                rezultat += "\\t";
                break;
            default:
                rezultat.push_back(ch);
                break;
        }
    }
    return rezultat;
}

} // namespace loglens::internal
