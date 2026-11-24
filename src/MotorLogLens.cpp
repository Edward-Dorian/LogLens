#include "MotorLogLens.h"

#include <algorithm>
#include <fstream>
#include <optional>
#include <sstream>
#include <utility>

#include "TimestampLog.h"
#include "internal/TextUtils.h"

namespace {
constexpr int kCodHttpMinim = 100;
constexpr int kCodHttpMaxim = 599;
constexpr int kScorMaxim = 100;
constexpr int kPragSeveritateCritical = 80;
constexpr int kPragSeveritateHigh = 60;
constexpr int kPragSeveritateMedium = 40;
constexpr int kPragIncidenteCritice = 3;
constexpr int kBonusPerIncidentSuplimentar = 5;
constexpr int kPragEvenimentRiscant = 50;
constexpr double kPondereEvenimenteRiscante = 35.0;
constexpr double kPondereEroriCritice = 15.0;
constexpr std::size_t kLimitaAfisareEvenimente = 5;
constexpr std::size_t kLimitaTopProfiluriIP = 5;

struct GrupEvenimenteIP {
    std::string ip;
    std::vector<EvenimentSecuritate> evenimente;
};

struct RezultatFereastra {
    int numarIncidente{0};
    int sumaScorRisc{0};
    bool areEroareCritica{false};
};

bool parseazaIntregStrict(const std::string& text, int& valoare) {
    if (text.empty()) {
        return false;
    }
    std::istringstream iss(text);
    int rezultat{0};
    char rest{'\0'};
    if (!(iss >> rezultat) || (iss >> rest)) {
        return false;
    }
    valoare = rezultat;
    return true;
}

RezultatFereastra calculeazaFereastraMaxima(const std::vector<EvenimentSecuritate>& evenimenteSortate,
                                            int fereastraSecunde) {
    RezultatFereastra celMaiBun{};
    if (evenimenteSortate.empty()) {
        return celMaiBun;
    }

    if (fereastraSecunde == 0) {
        for (const EvenimentSecuritate& ev : evenimenteSortate) {
            ++celMaiBun.numarIncidente;
            celMaiBun.sumaScorRisc += ev.calculeazaScorRisc();
            celMaiBun.areEroareCritica = celMaiBun.areEroareCritica || ev.esteEroareCritica();
        }
        return celMaiBun;
    }

    // Algoritm cu doi pointeri pe evenimentele sortate cronologic pentru fereastra maxima <= fereastraSecunde.
    std::size_t stanga{0};
    int sumaCurenta{0};
    int numarCriticeCurente{0};

    for (std::size_t dreapta = 0; dreapta < evenimenteSortate.size(); ++dreapta) {
        sumaCurenta += evenimenteSortate[dreapta].calculeazaScorRisc();
        if (evenimenteSortate[dreapta].esteEroareCritica()) {
            ++numarCriticeCurente;
        }

        while (stanga < dreapta &&
               evenimenteSortate[dreapta].getTimestamp().diferentaSecunde(
                   evenimenteSortate[stanga].getTimestamp()) > fereastraSecunde) {
            sumaCurenta -= evenimenteSortate[stanga].calculeazaScorRisc();
            if (evenimenteSortate[stanga].esteEroareCritica()) {
                --numarCriticeCurente;
            }
            ++stanga;
        }

        const int incidenteCurente = static_cast<int>(dreapta - stanga + 1);
        if (incidenteCurente > celMaiBun.numarIncidente ||
            (incidenteCurente == celMaiBun.numarIncidente && sumaCurenta > celMaiBun.sumaScorRisc)) {
            celMaiBun.numarIncidente = incidenteCurente;
            celMaiBun.sumaScorRisc = sumaCurenta;
            celMaiBun.areEroareCritica = numarCriticeCurente > 0;
        }
    }

    return celMaiBun;
}

Severitate determinaSeveritate(int scorRisc, int numarIncidente, bool areEroareCritica) {
    if (scorRisc >= kPragSeveritateCritical ||
        (areEroareCritica && numarIncidente >= kPragIncidenteCritice)) {
        return Severitate::Critical;
    }
    if (scorRisc >= kPragSeveritateHigh) {
        return Severitate::High;
    }
    if (scorRisc >= kPragSeveritateMedium) {
        return Severitate::Medium;
    }
    return Severitate::Low;
}

std::string construiesteRecomandare(const std::string& tipAmenintare) {
    if (tipAmenintare == "BRUTE_FORCE") {
        return "Blocheaza temporar IP-ul sursa si activeaza rate-limiting pe serviciul de autentificare.";
    }
    if (tipAmenintare == "ERROR_SPIKE") {
        return "Investigheaza imediat logurile serviciului afectat si verifica resursele serverului.";
    }
    if (tipAmenintare == "SUSPICIOUS_PAYLOAD") {
        return "Blocheaza cererile din acest IP in WAF si auditeaza validarea parametrilor de intrare.";
    }
    return "Monitorizeaza traficul provenit de la IP-ul sursa si revizuieste regulile de securitate.";
}
} // namespace

MotorLogLens::MotorLogLens(std::string numeServer_)
    : numeServer{std::move(numeServer_)},
      evenimente{},
      reguli{},
      alerte{} {}

MotorLogLens::MotorLogLens(const MotorLogLens& other) // NOLINT(modernize-use-equals-default)
    : numeServer{other.numeServer},
      evenimente{other.evenimente},
      reguli{other.reguli},
      alerte{other.alerte} {}

MotorLogLens& MotorLogLens::operator=(const MotorLogLens& other) {
    if (this == &other) {
        return *this;
    }

    numeServer = other.numeServer;
    evenimente = other.evenimente;
    reguli = other.reguli;
    alerte = other.alerte;
    return *this;
}

MotorLogLens::~MotorLogLens() {} // NOLINT(modernize-use-equals-default)

bool MotorLogLens::contineRegula(const RegulaDetectie& regula) const {
    return std::any_of(reguli.begin(), reguli.end(),
                       [&regula](const RegulaDetectie& existenta) { return existenta == regula; });
}

void MotorLogLens::adaugaRegula(const RegulaDetectie& regula) {
    if (!contineRegula(regula)) {
        reguli.push_back(regula);
    }
}

// Format asteptat pe linie: NUME|CUVINTE_CHEIE|PRAG_INCIDENTE|SCOR_MINIM|ACTIVA|FEREASTRA_SECUNDE (comentarii cu '#').
int MotorLogLens::incarcaReguliDinFisier(const std::string& caleFisier) {
    std::ifstream fisier(caleFisier);
    if (!fisier.is_open()) {
        return 0;
    }

    int reguliValide{0};
    std::string linieBruta;
    while (std::getline(fisier, linieBruta)) {
        const std::string linie = loglens::internal::curataSfarsitLinie(linieBruta);
        if (linie.empty() || linie[0] == '#') {
            continue;
        }

        std::istringstream iss(linie);
        std::string nume;
        std::string cuvinteCheie;
        std::string pragStr;
        std::string scorMinimStr;
        std::string activaStr;
        std::string fereastraStr;

        if (!std::getline(iss, nume, '|') ||
            !std::getline(iss, cuvinteCheie, '|') ||
            !std::getline(iss, pragStr, '|') ||
            !std::getline(iss, scorMinimStr, '|') ||
            !std::getline(iss, activaStr, '|') ||
            !std::getline(iss, fereastraStr)) {
            continue;
        }

        int pragIncidente{0};
        int scorMinim{0};
        int activaFlag{0};
        int fereastraSecunde{0};
        if (nume.empty() ||
            !parseazaIntregStrict(pragStr, pragIncidente) || pragIncidente <= 0 ||
            !parseazaIntregStrict(scorMinimStr, scorMinim) || scorMinim < 0 || scorMinim > kScorMaxim ||
            !parseazaIntregStrict(activaStr, activaFlag) || (activaFlag != 0 && activaFlag != 1) ||
            !parseazaIntregStrict(fereastraStr, fereastraSecunde) || fereastraSecunde < 0) {
            continue;
        }

        adaugaRegula(RegulaDetectie{
            nume, cuvinteCheie, pragIncidente, scorMinim, activaFlag == 1, fereastraSecunde});
        ++reguliValide;
    }

    return reguliValide;
}

// Format asteptat pe linie: TIMESTAMP|IP|SERVICIU|COD_STATUS|MESAJ (comentarii cu '#').
int MotorLogLens::incarcaLogDinFisier(const std::string& caleFisier) {
    std::ifstream fisier(caleFisier);
    if (!fisier.is_open()) {
        return 0;
    }

    int liniiValide{0};
    std::string linieBruta;
    while (std::getline(fisier, linieBruta)) {
        const std::string linie = loglens::internal::curataSfarsitLinie(linieBruta);
        if (linie.empty() || linie[0] == '#') {
            continue;
        }

        std::istringstream iss(linie);
        std::string timestampStr;
        std::string ip;
        std::string serviciu;
        std::string codStatusStr;
        std::string mesaj;

        if (!std::getline(iss, timestampStr, '|') ||
            !std::getline(iss, ip, '|') ||
            !std::getline(iss, serviciu, '|') ||
            !std::getline(iss, codStatusStr, '|') ||
            !std::getline(iss, mesaj)) {
            continue;
        }

        const std::optional<TimestampLog> ts = parseazaTimestampLog(timestampStr);
        int codStatus{0};
        if (!ts.has_value() || ip.empty() || serviciu.empty() || mesaj.empty() ||
            !parseazaIntregStrict(codStatusStr, codStatus) ||
            codStatus < kCodHttpMinim || codStatus > kCodHttpMaxim) {
            continue;
        }

        evenimente.emplace_back(*ts, ip, serviciu, codStatus, mesaj);
        ++liniiValide;
    }

    return liniiValide;
}

void MotorLogLens::analizeazaAmenintari() {
    // Resetam alertele vechi pentru a putea relua analiza fara duplicate.
    alerte.clear();

    for (const RegulaDetectie& regula : reguli) {
        if (!regula.esteActiva()) {
            continue;
        }

        // Pentru fiecare regula activa, colectam evenimentele potrivite grupate pe adresa IP sursa.
        std::vector<GrupEvenimenteIP> grupuri;

        for (const EvenimentSecuritate& ev : evenimente) {
            if (!regula.sePotriveste(ev)) {
                continue;
            }

            const std::string& ip = ev.getSursaIP();
            bool gasit{false};
            for (GrupEvenimenteIP& grup : grupuri) {
                if (grup.ip == ip) {
                    grup.evenimente.push_back(ev);
                    gasit = true;
                    break;
                }
            }

            if (!gasit) {
                grupuri.push_back(GrupEvenimenteIP{ip, {ev}});
            }
        }

        // Sortam cronologic evenimentele fiecarui IP si aplicam fereastra glisanta a regulii.
        for (GrupEvenimenteIP& grup : grupuri) {
            std::sort(grup.evenimente.begin(), grup.evenimente.end(),
                      [](const EvenimentSecuritate& a, const EvenimentSecuritate& b) {
                          return a.getTimestamp() < b.getTimestamp();
                      });

            const RezultatFereastra fereastra =
                calculeazaFereastraMaxima(grup.evenimente, regula.getFereastraSecunde());
            if (fereastra.numarIncidente < regula.getPragIncidente()) {
                continue;
            }

            const int scorMediu = fereastra.sumaScorRisc / fereastra.numarIncidente;
            const int bonusVolum = (fereastra.numarIncidente - 1) * kBonusPerIncidentSuplimentar;
            const int scorFinal = std::min(kScorMaxim, scorMediu + bonusVolum);
            const Severitate severitate = determinaSeveritate(
                scorFinal, fereastra.numarIncidente, fereastra.areEroareCritica);
            const std::string recomandare = construiesteRecomandare(regula.getNume());

            alerte.emplace_back(regula.getNume(),
                                grup.ip,
                                severitate,
                                fereastra.numarIncidente,
                                scorFinal,
                                recomandare);
        }
    }
}

// Scorul porneste de la 100 si scade proportional cu ponderea evenimentelor riscante/critice si penalizarea alertelor.
int MotorLogLens::calculeazaScorSanatateServer() const {
    if (evenimente.empty()) {
        return kScorMaxim;
    }

    int numarEvenimenteRiscante{0};
    int numarEroriCritice{0};
    for (const EvenimentSecuritate& ev : evenimente) {
        if (ev.calculeazaScorRisc() >= kPragEvenimentRiscant) {
            ++numarEvenimenteRiscante;
        }
        if (ev.esteEroareCritica()) {
            ++numarEroriCritice;
        }
    }

    const auto totalEvenimente = static_cast<double>(evenimente.size());
    const double proportieRiscante = static_cast<double>(numarEvenimenteRiscante) / totalEvenimente;
    const double proportieCritice = static_cast<double>(numarEroriCritice) / totalEvenimente;

    int penalizare = static_cast<int>(proportieRiscante * kPondereEvenimenteRiscante) +
                     static_cast<int>(proportieCritice * kPondereEroriCritice);

    for (const AlertaSecuritate& alerta : alerte) {
        penalizare += alerta.calculeazaPenalizareSanatate();
    }

    return std::max(0, kScorMaxim - penalizare);
}

std::vector<EvenimentSecuritate> MotorLogLens::extrageEvenimentePerIP(const std::string& ip) const {
    std::vector<EvenimentSecuritate> rezultat;
    for (const EvenimentSecuritate& ev : evenimente) {
        if (ev.getSursaIP() == ip) {
            rezultat.push_back(ev);
        }
    }
    return rezultat;
}

std::vector<ProfilIP> MotorLogLens::construiesteProfiluriIP() const {
    std::vector<ProfilIP> profiluri;

    for (const EvenimentSecuritate& ev : evenimente) {
        bool gasit{false};
        for (ProfilIP& profil : profiluri) {
            if (profil.getAdresaIP() == ev.getSursaIP()) {
                profil.adaugaEveniment(ev);
                gasit = true;
                break;
            }
        }
        if (!gasit) {
            profiluri.emplace_back(ev);
        }
    }

    std::sort(profiluri.begin(), profiluri.end(),
              [](const ProfilIP& a, const ProfilIP& b) {
                  const int scorA = a.calculeazaScorPericulozitate();
                  const int scorB = b.calculeazaScorPericulozitate();
                  if (scorA != scorB) {
                      return scorA > scorB;
                  }
                  return a.getAdresaIP() < b.getAdresaIP();
              });

    return profiluri;
}

RaportSecuritate MotorLogLens::genereazaRaportSecuritate() const {
    std::optional<TimestampLog> inceput;
    std::optional<TimestampLog> sfarsit;
    int erori4xx{0};
    int erori5xx{0};
    std::vector<std::pair<std::string, int>> sumarServicii;

    for (const EvenimentSecuritate& ev : evenimente) {
        const TimestampLog& ts = ev.getTimestamp();
        if (!inceput.has_value() || ts < *inceput) {
            inceput = ts;
        }
        if (!sfarsit.has_value() || ts > *sfarsit) {
            sfarsit = ts;
        }

        if (ev.esteEroareClient()) {
            ++erori4xx;
        } else if (ev.esteEroareServer()) {
            ++erori5xx;
        }

        if (ev.calculeazaScorRisc() >= kPragEvenimentRiscant) {
            const std::string& serviciu = ev.getServiciu();
            bool gasit{false};
            for (auto& [numeServiciu, numar] : sumarServicii) {
                if (numeServiciu == serviciu) {
                    ++numar;
                    gasit = true;
                    break;
                }
            }
            if (!gasit) {
                sumarServicii.emplace_back(serviciu, 1);
            }
        }
    }

    std::sort(sumarServicii.begin(), sumarServicii.end(),
              [](const std::pair<std::string, int>& a, const std::pair<std::string, int>& b) {
                  if (a.second != b.second) {
                      return a.second > b.second;
                  }
                  return a.first < b.first;
              });

    std::vector<ProfilIP> topProfiluri = construiesteProfiluriIP();
    if (topProfiluri.size() > kLimitaTopProfiluriIP) {
        topProfiluri.erase(topProfiluri.begin() + static_cast<std::ptrdiff_t>(kLimitaTopProfiluriIP),
                           topProfiluri.end());
    }

    return RaportSecuritate{
        numeServer,
        inceput,
        sfarsit,
        calculeazaScorSanatateServer(),
        static_cast<int>(evenimente.size()),
        erori4xx,
        erori5xx,
        std::move(sumarServicii),
        std::move(topProfiluri),
        alerte
    };
}

const std::vector<AlertaSecuritate>& MotorLogLens::getAlerte() const {
    return alerte;
}

std::ostream& operator<<(std::ostream& os, const MotorLogLens& motor) {
    os << "=== MotorLogLens [" << motor.numeServer << "] ===\n";
    os << "Evenimente incarcate: " << motor.evenimente.size()
       << " | Reguli configurate: " << motor.reguli.size()
       << " | Alerte active: " << motor.alerte.size()
       << " | Sanatate server: " << motor.calculeazaScorSanatateServer() << "%\n";

    os << "\n--- Reguli de detectie ---\n";
    for (const RegulaDetectie& regula : motor.reguli) {
        os << "  * " << regula << "\n";
    }

    os << "\n--- Primele evenimente analizate ---\n";
    const std::size_t limitaAfisare = std::min(motor.evenimente.size(), kLimitaAfisareEvenimente);
    for (std::size_t i = 0; i < limitaAfisare; ++i) {
        os << "  - " << motor.evenimente[i] << "\n";
    }
    if (motor.evenimente.size() > limitaAfisare) {
        os << "  ... (inca " << (motor.evenimente.size() - limitaAfisare) << " evenimente)\n";
    }

    os << "\n--- Alerte generate ---\n";
    if (motor.alerte.empty()) {
        os << "  (nicio alerta activa)\n";
    } else {
        for (const AlertaSecuritate& alerta : motor.alerte) {
            os << "  ! " << alerta << "\n";
        }
    }
    return os;
}
