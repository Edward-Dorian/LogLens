#include "ProfilIP.h"

#include <algorithm>
#include <string_view>

namespace {
constexpr int kPragEvenimentRiscant = 50;
constexpr int kPragScorMalitios = 75;
constexpr int kPragIncidenteMalitios = 5;
constexpr int kPragScorSuspect = 50;
constexpr int kPragIncidenteSuspect = 2;
constexpr int kPragScorMonitorizat = 25;
constexpr std::size_t kPragServiciiReconnaissance = 3;

constexpr int kBonusEroareCritica = 35;
constexpr int kBonusEvenimentRiscant = 8;
constexpr int kBonusServiciuReconnaissance = 12;

std::string_view nivelReputatieToString(NivelReputatie nivel) {
    switch (nivel) {
        case NivelReputatie::Curat:
            return "CURAT";
        case NivelReputatie::Monitorizat:
            return "MONITORIZAT";
        case NivelReputatie::Suspect:
            return "SUSPECT";
        case NivelReputatie::Malitios:
            return "MALITIOS";
    }
    return "CURAT";
}
} // namespace

std::ostream& operator<<(std::ostream& os, NivelReputatie nivel) {
    os << nivelReputatieToString(nivel);
    return os;
}

ProfilIP::ProfilIP(const EvenimentSecuritate& primEveniment)
    : adresaIP{primEveniment.getSursaIP()},
      primaActivitate{primEveniment.getTimestamp()},
      ultimaActivitate{primEveniment.getTimestamp()},
      totalEvenimente{1},
      evenimenteRiscante{primEveniment.calculeazaScorRisc() >= kPragEvenimentRiscant ? 1 : 0},
      eroriCritice{primEveniment.esteEroareCritica() ? 1 : 0},
      sumaScorRisc{primEveniment.calculeazaScorRisc()},
      scorMaxim{primEveniment.calculeazaScorRisc()},
      serviciiAccesate{primEveniment.getServiciu()} {}

void ProfilIP::adaugaEveniment(const EvenimentSecuritate& ev) {
    if (ev.getSursaIP() != adresaIP) {
        return;
    }

    if (ev.getTimestamp() < primaActivitate) {
        primaActivitate = ev.getTimestamp();
    }
    if (ev.getTimestamp() > ultimaActivitate) {
        ultimaActivitate = ev.getTimestamp();
    }

    const int scor = ev.calculeazaScorRisc();
    ++totalEvenimente;
    if (scor >= kPragEvenimentRiscant) {
        ++evenimenteRiscante;
    }
    if (ev.esteEroareCritica()) {
        ++eroriCritice;
    }
    sumaScorRisc += scor;
    scorMaxim = std::max(scorMaxim, scor);

    const std::string& serviciu = ev.getServiciu();
    if (std::find(serviciiAccesate.begin(), serviciiAccesate.end(), serviciu) ==
        serviciiAccesate.end()) {
        serviciiAccesate.push_back(serviciu);
    }
}

const std::string& ProfilIP::getAdresaIP() const {
    return adresaIP;
}

std::size_t ProfilIP::getNumarServiciiAccesate() const {
    return serviciiAccesate.size();
}

int ProfilIP::calculeazaScorMediuRisc() const {
    if (totalEvenimente <= 0) {
        return 0;
    }
    return sumaScorRisc / totalEvenimente;
}

long long ProfilIP::calculeazaDurataActivitateSecunde() const {
    return ultimaActivitate.diferentaSecunde(primaActivitate);
}

NivelReputatie ProfilIP::determinaReputatie() const {
    const bool areReconnaissance = serviciiAccesate.size() >= kPragServiciiReconnaissance;

    if (eroriCritice >= 1 || scorMaxim >= kPragScorMalitios ||
        evenimenteRiscante >= kPragIncidenteMalitios) {
        return NivelReputatie::Malitios;
    }
    if (evenimenteRiscante >= kPragIncidenteSuspect || scorMaxim >= kPragScorSuspect ||
        (areReconnaissance && evenimenteRiscante >= 1)) {
        return NivelReputatie::Suspect;
    }
    if (evenimenteRiscante >= 1 || scorMaxim >= kPragScorMonitorizat ||
        (areReconnaissance && scorMaxim > 0)) {
        return NivelReputatie::Monitorizat;
    }
    return NivelReputatie::Curat;
}

int ProfilIP::calculeazaScorPericulozitate() const {
    int scor = scorMaxim + calculeazaScorMediuRisc() +
               eroriCritice * kBonusEroareCritica +
               evenimenteRiscante * kBonusEvenimentRiscant;
    if (serviciiAccesate.size() >= kPragServiciiReconnaissance && scorMaxim > 0) {
        scor += kBonusServiciuReconnaissance;
    }
    return scor;
}

std::ostream& operator<<(std::ostream& os, const ProfilIP& profil) {
    os << "[" << profil.determinaReputatie() << "] IP: " << profil.adresaIP
       << " | Evenimente: " << profil.totalEvenimente
       << " (riscante: " << profil.evenimenteRiscante
       << ", critice: " << profil.eroriCritice << ")"
       << " | Risc mediu/max: " << profil.calculeazaScorMediuRisc()
       << "/" << profil.scorMaxim
       << " | Servicii distincte: " << profil.serviciiAccesate.size()
       << " | Interval: " << profil.primaActivitate << " -> " << profil.ultimaActivitate
       << " (" << profil.calculeazaDurataActivitateSecunde() << "s)";
    return os;
}
