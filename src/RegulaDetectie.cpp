#include "RegulaDetectie.h"

#include <algorithm>
#include <sstream>
#include <utility>

#include "internal/TextUtils.h"

namespace {
std::vector<std::string> parseazaTermeniCheie(const std::string& cuvantCheie) {
    std::vector<std::string> termeni;
    std::istringstream iss(cuvantCheie);
    std::string termen;
    while (std::getline(iss, termen, ',')) {
        const std::string curat =
            loglens::internal::transformaInLitereMici(loglens::internal::eliminaSpatiiMargini(termen));
        if (!curat.empty()) {
            termeni.push_back(curat);
        }
    }
    return termeni;
}
} // namespace

RegulaDetectie::RegulaDetectie(std::string nume_,
                               const std::string& cuvantCheie_,
                               int pragIncidente_,
                               int scorMinim_,
                               bool activa_,
                               int fereastraSecunde_)
    : nume{std::move(nume_)},
      termeniCheie{parseazaTermeniCheie(cuvantCheie_)},
      pragIncidente{pragIncidente_},
      scorMinim{scorMinim_},
      activa{activa_},
      fereastraSecunde{fereastraSecunde_} {}

const std::string& RegulaDetectie::getNume() const {
    return nume;
}

int RegulaDetectie::getPragIncidente() const {
    return pragIncidente;
}

bool RegulaDetectie::esteActiva() const {
    return activa;
}

int RegulaDetectie::getFereastraSecunde() const {
    return fereastraSecunde;
}

bool RegulaDetectie::contineCuvantCheie(const std::string& text) const {
    if (termeniCheie.empty()) {
        return true;
    }

    const std::string textMic = loglens::internal::transformaInLitereMici(text);
    return std::any_of(termeniCheie.begin(), termeniCheie.end(),
                       [&textMic](const std::string& cheie) {
                           return textMic.find(cheie) != std::string::npos;
                       });
}

bool RegulaDetectie::sePotriveste(const EvenimentSecuritate& ev) const {
    if (!activa) {
        return false;
    }

    if (ev.calculeazaScorRisc() < scorMinim) {
        return false;
    }

    return contineCuvantCheie(ev.getMesaj()) || contineCuvantCheie(ev.getServiciu());
}

std::ostream& operator<<(std::ostream& os, const RegulaDetectie& regula) {
    os << "Regula [" << regula.nume << "] | Cuvinte-cheie: \"";
    for (std::size_t i = 0; i < regula.termeniCheie.size(); ++i) {
        if (i > 0) {
            os << ", ";
        }
        os << regula.termeniCheie[i];
    }
    os << "\""
       << " | Prag incidente: " << regula.pragIncidente
       << " | Scor minim: " << regula.scorMinim
       << " | Fereastra: ";
    if (regula.fereastraSecunde > 0) {
        os << regula.fereastraSecunde << "s";
    } else {
        os << "globala";
    }
    os << " | Stare: " << (regula.activa ? "ACTIVA" : "INACTIVA");
    return os;
}
