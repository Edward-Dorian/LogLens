#pragma once

#include <cstddef>
#include <ostream>
#include <string>
#include <vector>

#include "EvenimentSecuritate.h"
#include "TimestampLog.h"

enum class NivelReputatie {
    Curat,
    Monitorizat,
    Suspect,
    Malitios
};

std::ostream& operator<<(std::ostream& os, NivelReputatie nivel);

class ProfilIP {
private:
    std::string adresaIP;
    TimestampLog primaActivitate;
    TimestampLog ultimaActivitate;
    int totalEvenimente;
    int evenimenteRiscante;
    int eroriCritice;
    int sumaScorRisc;
    int scorMaxim;
    std::vector<std::string> serviciiAccesate;

public:
    explicit ProfilIP(const EvenimentSecuritate& primEveniment);

    void adaugaEveniment(const EvenimentSecuritate& ev);

    [[nodiscard]] const std::string& getAdresaIP() const;
    [[nodiscard]] std::size_t getNumarServiciiAccesate() const;

    [[nodiscard]] int calculeazaScorMediuRisc() const;
    [[nodiscard]] long long calculeazaDurataActivitateSecunde() const;
    [[nodiscard]] NivelReputatie determinaReputatie() const;
    [[nodiscard]] int calculeazaScorPericulozitate() const;

    friend std::ostream& operator<<(std::ostream& os, const ProfilIP& profil);
};
