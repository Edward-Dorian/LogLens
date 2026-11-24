#include "AlertaSecuritate.h"

#include <sstream>
#include <string_view>
#include <utility>

#include "internal/TextUtils.h"

namespace {
constexpr int kPenalizareCritical = 18;
constexpr int kPenalizareHigh = 12;
constexpr int kPenalizareMedium = 6;
constexpr int kPenalizareLow = 3;
constexpr int kPragScorRiscExtrem = 85;
constexpr int kPenalizareSuplimentaraRiscExtrem = 2;

std::string_view severitateToString(Severitate severitate) {
    switch (severitate) {
        case Severitate::Low:
            return "LOW";
        case Severitate::Medium:
            return "MEDIUM";
        case Severitate::High:
            return "HIGH";
        case Severitate::Critical:
            return "CRITICAL";
    }
    return "LOW";
}
} // namespace

std::ostream& operator<<(std::ostream& os, Severitate severitate) {
    os << severitateToString(severitate);
    return os;
}

AlertaSecuritate::AlertaSecuritate(std::string tipAmenintare_,
                                   std::string sursaIP_,
                                   Severitate severitate_,
                                   int numarIncidente_,
                                   int scorRisc_,
                                   std::string recomandare_)
    : tipAmenintare{std::move(tipAmenintare_)},
      sursaIP{std::move(sursaIP_)},
      severitate{severitate_},
      numarIncidente{numarIncidente_},
      scorRisc{scorRisc_},
      recomandare{std::move(recomandare_)} {}

Severitate AlertaSecuritate::getSeveritate() const {
    return severitate;
}

int AlertaSecuritate::calculeazaPenalizareSanatate() const {
    int penalizare{0};
    switch (severitate) {
        case Severitate::Critical:
            penalizare = kPenalizareCritical;
            break;
        case Severitate::High:
            penalizare = kPenalizareHigh;
            break;
        case Severitate::Medium:
            penalizare = kPenalizareMedium;
            break;
        case Severitate::Low:
            penalizare = kPenalizareLow;
            break;
    }

    if (scorRisc >= kPragScorRiscExtrem) {
        penalizare += kPenalizareSuplimentaraRiscExtrem;
    }

    return penalizare;
}

std::string AlertaSecuritate::formateazaPentruSecurityFlow() const {
    std::ostringstream oss;
    oss << "{\n"
        << R"(  "threatType": ")" << loglens::internal::scapaCaractereJson(tipAmenintare) << "\",\n"
        << R"(  "sourceIp": ")" << loglens::internal::scapaCaractereJson(sursaIP) << "\",\n"
        << R"(  "severity": ")" << severitateToString(severitate) << "\",\n"
        << R"(  "incidentCount": )" << numarIncidente << ",\n"
        << R"(  "riskScore": )" << scorRisc << ",\n"
        << R"(  "recommendation": ")" << loglens::internal::scapaCaractereJson(recomandare) << "\"\n"
        << "}";
    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const AlertaSecuritate& alerta) {
    os << "[ALERTA " << alerta.severitate << "] "
       << alerta.tipAmenintare
       << " | IP: " << alerta.sursaIP
       << " | Incidente: " << alerta.numarIncidente
       << " | Scor risc: " << alerta.scorRisc << "/100"
       << " | Recomandare: " << alerta.recomandare;
    return os;
}
