#include "RaportSecuritate.h"

#include <algorithm>
#include <sstream>
#include <utility>

#include "internal/TextUtils.h"

namespace {
std::string formateazaTimestamp(const TimestampLog& ts) {
    std::ostringstream oss;
    oss << ts;
    return oss.str();
}

std::string formateazaReputatie(NivelReputatie nivel) {
    std::ostringstream oss;
    oss << nivel;
    return oss.str();
}

std::string indenteazaBloc(const std::string& bloc, const std::string& indentare) {
    std::istringstream iss(bloc);
    std::ostringstream oss;
    std::string linie;
    bool primaLinie{true};
    while (std::getline(iss, linie)) {
        if (!primaLinie) {
            oss << "\n";
        }
        oss << indentare << linie;
        primaLinie = false;
    }
    return oss.str();
}
} // namespace

RaportSecuritate::RaportSecuritate(std::string numeServer_,
                                   std::optional<TimestampLog> inceputInterval_,
                                   std::optional<TimestampLog> sfarsitInterval_,
                                   int scorSanatate_,
                                   int totalEvenimente_,
                                   int numarErori4xx_,
                                   int numarErori5xx_,
                                   std::vector<std::pair<std::string, int>> sumarServicii_,
                                   std::vector<ProfilIP> topProfiluriIP_,
                                   std::vector<AlertaSecuritate> alerte_)
    : numeServer{std::move(numeServer_)},
      inceputInterval{inceputInterval_},
      sfarsitInterval{sfarsitInterval_},
      scorSanatate{scorSanatate_},
      totalEvenimente{totalEvenimente_},
      numarErori4xx{numarErori4xx_},
      numarErori5xx{numarErori5xx_},
      sumarServicii{std::move(sumarServicii_)},
      topProfiluriIP{std::move(topProfiluriIP_)},
      alerte{std::move(alerte_)} {}

int RaportSecuritate::numaraAlerteCuSeveritate(Severitate severitate) const {
    return static_cast<int>(std::count_if(
        alerte.begin(), alerte.end(),
        [severitate](const AlertaSecuritate& alerta) {
            return alerta.getSeveritate() == severitate;
        }));
}

std::string RaportSecuritate::formateazaJsonComplet() const {
    const int alerteCritical = numaraAlerteCuSeveritate(Severitate::Critical);
    const int alerteHigh = numaraAlerteCuSeveritate(Severitate::High);
    const int alerteMedium = numaraAlerteCuSeveritate(Severitate::Medium);
    const int alerteLow = numaraAlerteCuSeveritate(Severitate::Low);

    std::ostringstream oss;
    oss << "{\n"
        << R"(  "serverName": ")" << loglens::internal::scapaCaractereJson(numeServer) << "\",\n"
        << R"(  "timeRange": {)" << "\n";

    if (inceputInterval.has_value() && sfarsitInterval.has_value()) {
        oss << R"(    "start": ")" << formateazaTimestamp(*inceputInterval) << "\",\n"
            << R"(    "end": ")" << formateazaTimestamp(*sfarsitInterval) << "\"\n";
    } else {
        oss << R"(    "start": null,)" << "\n"
            << R"(    "end": null)" << "\n";
    }

    oss << "  },\n"
        << R"(  "healthScore": )" << scorSanatate << ",\n"
        << R"(  "totalEvents": )" << totalEvenimente << ",\n"
        << R"(  "httpErrors": {)" << "\n"
        << R"(    "4xx": )" << numarErori4xx << ",\n"
        << R"(    "5xx": )" << numarErori5xx << "\n"
        << "  },\n"
        << R"(  "alertDistribution": {)" << "\n"
        << R"(    "critical": )" << alerteCritical << ",\n"
        << R"(    "high": )" << alerteHigh << ",\n"
        << R"(    "medium": )" << alerteMedium << ",\n"
        << R"(    "low": )" << alerteLow << "\n"
        << "  },\n"
        << R"(  "affectedServices": [)";

    if (!sumarServicii.empty()) {
        oss << "\n";
        for (std::size_t i = 0; i < sumarServicii.size(); ++i) {
            const auto& [serviciu, incidente] = sumarServicii[i];
            oss << R"(    { "service": ")" << loglens::internal::scapaCaractereJson(serviciu)
                << R"(", "riskyEvents": )" << incidente << " }";
            if (i + 1 < sumarServicii.size()) {
                oss << ",";
            }
            oss << "\n";
        }
        oss << "  ";
    }
    oss << "],\n"
        << R"(  "topIpProfiles": [)";

    if (!topProfiluriIP.empty()) {
        oss << "\n";
        for (std::size_t i = 0; i < topProfiluriIP.size(); ++i) {
            const ProfilIP& profil = topProfiluriIP[i];
            oss << R"(    { "ip": ")" << loglens::internal::scapaCaractereJson(profil.getAdresaIP())
                << R"(", "reputation": ")" << formateazaReputatie(profil.determinaReputatie())
                << R"(", "avgRisk": )" << profil.calculeazaScorMediuRisc()
                << R"(, "distinctServices": )" << profil.getNumarServiciiAccesate()
                << R"(, "activityDurationSec": )" << profil.calculeazaDurataActivitateSecunde()
                << " }";
            if (i + 1 < topProfiluriIP.size()) {
                oss << ",";
            }
            oss << "\n";
        }
        oss << "  ";
    }
    oss << "],\n"
        << R"(  "alerts": [)";

    if (!alerte.empty()) {
        oss << "\n";
        for (std::size_t i = 0; i < alerte.size(); ++i) {
            oss << indenteazaBloc(alerte[i].formateazaPentruSecurityFlow(), "    ");
            if (i + 1 < alerte.size()) {
                oss << ",";
            }
            oss << "\n";
        }
        oss << "  ";
    }
    oss << "]\n"
        << "}";

    return oss.str();
}

std::ostream& operator<<(std::ostream& os, const RaportSecuritate& raport) {
    os << "=== Raport Securitate [" << raport.numeServer << "] ===\n";
    os << "Interval analizat: ";
    if (raport.inceputInterval.has_value() && raport.sfarsitInterval.has_value()) {
        os << *raport.inceputInterval << " -> " << *raport.sfarsitInterval << "\n";
    } else {
        os << "N/A (fara evenimente)\n";
    }

    os << "Sanatate server: " << raport.scorSanatate << "%"
       << " | Total evenimente: " << raport.totalEvenimente
       << " | Erori HTTP: 4xx=" << raport.numarErori4xx
       << ", 5xx=" << raport.numarErori5xx << "\n";

    os << "Distributie alerte: CRITICAL=" << raport.numaraAlerteCuSeveritate(Severitate::Critical)
       << ", HIGH=" << raport.numaraAlerteCuSeveritate(Severitate::High)
       << ", MEDIUM=" << raport.numaraAlerteCuSeveritate(Severitate::Medium)
       << ", LOW=" << raport.numaraAlerteCuSeveritate(Severitate::Low) << "\n";

    os << "\n--- Servicii afectate ---\n";
    if (raport.sumarServicii.empty()) {
        os << "  (niciun serviciu afectat)\n";
    } else {
        for (const auto& [serviciu, incidente] : raport.sumarServicii) {
            os << "  * " << serviciu << ": " << incidente << " evenimente riscante\n";
        }
    }

    os << "\n--- Top profiluri IP ---\n";
    if (raport.topProfiluriIP.empty()) {
        os << "  (niciun profil IP)\n";
    } else {
        for (const ProfilIP& profil : raport.topProfiluriIP) {
            os << "  - " << profil << "\n";
        }
    }

    os << "\n--- Alerte incluse in raport ---\n";
    if (raport.alerte.empty()) {
        os << "  (nicio alerta activa)\n";
    } else {
        for (const AlertaSecuritate& alerta : raport.alerte) {
            os << "  ! " << alerta << "\n";
        }
    }
    return os;
}
