#include "EvenimentSecuritate.h"

#include <algorithm>
#include <array>
#include <string_view>
#include <utility>

#include "internal/TextUtils.h"

namespace {
constexpr int kCodEroareServerMin = 500;
constexpr int kCodEroareClientMin = 400;
constexpr int kCodNeautorizat = 401;
constexpr int kCodInterzis = 403;

constexpr int kScorEroareServer = 40;
constexpr int kScorAccesRespins = 30;
constexpr int kScorEroareClient = 15;
constexpr int kBonusServiciuSensibil = 15;
constexpr int kScorSemnaturaAtac = 55;
constexpr int kScorCuvantRisc = 15;
constexpr int kScorMaximRisc = 100;
constexpr int kPragEroareCritica = 70;

constexpr std::array<std::string_view, 6> kSemnaturiAtac = {
    "../",
    "/etc/passwd",
    "drop table",
    "union select",
    "<script",
    "cmd="
};

constexpr std::array<std::string_view, 5> kServiciiSensibile = {
    "auth",
    "ssh",
    "admin",
    "payments",
    "db"
};

constexpr std::array<std::string_view, 7> kCuvinteRisc = {
    "failed",
    "invalid password",
    "denied",
    "unauthorized",
    "timeout",
    "exception",
    "crash"
};
} // namespace

EvenimentSecuritate::EvenimentSecuritate(const TimestampLog& timestamp_,
                                         std::string sursaIP_,
                                         std::string serviciu_,
                                         int codStatus_,
                                         std::string mesaj_)
    : timestamp{timestamp_},
      sursaIP{std::move(sursaIP_)},
      serviciu{std::move(serviciu_)},
      codStatus{codStatus_},
      mesaj{std::move(mesaj_)} {}

const TimestampLog& EvenimentSecuritate::getTimestamp() const {
    return timestamp;
}

const std::string& EvenimentSecuritate::getSursaIP() const {
    return sursaIP;
}

const std::string& EvenimentSecuritate::getServiciu() const {
    return serviciu;
}

const std::string& EvenimentSecuritate::getMesaj() const {
    return mesaj;
}

bool EvenimentSecuritate::contineSemnaturaAtac() const {
    const std::string mesajMic = loglens::internal::transformaInLitereMici(mesaj);
    return std::any_of(kSemnaturiAtac.begin(), kSemnaturiAtac.end(),
                       [&mesajMic](std::string_view model) {
                           return mesajMic.find(model) != std::string::npos;
                       });
}

bool EvenimentSecuritate::esteServiciuSensibil() const {
    const std::string serviciuMic = loglens::internal::transformaInLitereMici(serviciu);
    return std::any_of(kServiciiSensibile.begin(), kServiciiSensibile.end(),
                       [&serviciuMic](std::string_view s) { return serviciuMic == s; });
}

int EvenimentSecuritate::calculeazaScorRisc() const {
    // Scor cumulativ (0-100): cod HTTP + semnături/cuvinte suspecte + bonus pentru servicii sensibile.
    int scor{0};

    if (codStatus >= kCodEroareServerMin) {
        scor += kScorEroareServer;
    } else if (codStatus == kCodNeautorizat || codStatus == kCodInterzis) {
        scor += kScorAccesRespins;
    } else if (codStatus >= kCodEroareClientMin) {
        scor += kScorEroareClient;
    }

    if (contineSemnaturaAtac()) {
        scor += kScorSemnaturaAtac;
    } else {
        const std::string mesajMic = loglens::internal::transformaInLitereMici(mesaj);
        const bool areCuvantRisc = std::any_of(
            kCuvinteRisc.begin(), kCuvinteRisc.end(),
            [&mesajMic](std::string_view model) {
                return mesajMic.find(model) != std::string::npos;
            });
        if (areCuvantRisc) {
            scor += kScorCuvantRisc;
        }
    }

    // Bonusul de serviciu sensibil se aplică doar dacă există deja un semnal de risc.
    if (scor > 0 && esteServiciuSensibil()) {
        scor += kBonusServiciuSensibil;
    }

    return std::min(kScorMaximRisc, scor);
}

bool EvenimentSecuritate::esteEroareCritica() const {
    return codStatus >= kCodEroareServerMin || calculeazaScorRisc() >= kPragEroareCritica;
}

bool EvenimentSecuritate::esteEroareClient() const {
    return codStatus >= kCodEroareClientMin && codStatus < kCodEroareServerMin;
}

bool EvenimentSecuritate::esteEroareServer() const {
    return codStatus >= kCodEroareServerMin;
}

std::ostream& operator<<(std::ostream& os, const EvenimentSecuritate& ev) {
    os << "[" << ev.timestamp << "] "
       << "IP: " << ev.sursaIP
       << " | Serviciu: " << ev.serviciu
       << " | Status: " << ev.codStatus
       << " | Risc: " << ev.calculeazaScorRisc() << "/100"
       << " | Mesaj: " << ev.mesaj;
    return os;
}
