#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "AlertaSecuritate.h"
#include "EvenimentSecuritate.h"
#include "ProfilIP.h"
#include "RaportSecuritate.h"
#include "RegulaDetectie.h"

class MotorLogLens {
private:
    std::string numeServer;
    std::vector<EvenimentSecuritate> evenimente;
    std::vector<RegulaDetectie> reguli;
    std::vector<AlertaSecuritate> alerte;

    [[nodiscard]] bool contineRegula(const RegulaDetectie& regula) const;

public:
    explicit MotorLogLens(std::string numeServer_);

    MotorLogLens(const MotorLogLens& other);
    MotorLogLens& operator=(const MotorLogLens& other);
    ~MotorLogLens();

    void adaugaRegula(const RegulaDetectie& regula);
    int incarcaReguliDinFisier(const std::string& caleFisier);
    int incarcaLogDinFisier(const std::string& caleFisier);
    void analizeazaAmenintari();

    [[nodiscard]] int calculeazaScorSanatateServer() const;
    [[nodiscard]] std::vector<EvenimentSecuritate> extrageEvenimentePerIP(const std::string& ip) const;
    [[nodiscard]] std::vector<ProfilIP> construiesteProfiluriIP() const;
    [[nodiscard]] RaportSecuritate genereazaRaportSecuritate() const;
    [[nodiscard]] const std::vector<AlertaSecuritate>& getAlerte() const;

    [[nodiscard]] bool operator==(const MotorLogLens& other) const = default;

    friend std::ostream& operator<<(std::ostream& os, const MotorLogLens& motor);
};
