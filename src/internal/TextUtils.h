#pragma once

#include <string>
#include <string_view>

namespace loglens::internal {

[[nodiscard]] std::string transformaInLitereMici(std::string_view text);
[[nodiscard]] std::string eliminaSpatiiMargini(std::string_view text);
[[nodiscard]] std::string curataSfarsitLinie(std::string_view linie);
[[nodiscard]] std::string scapaCaractereJson(std::string_view text);

} // namespace loglens::internal
