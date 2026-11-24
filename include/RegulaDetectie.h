#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "EvenimentSecuritate.h"

class RegulaDetectie {
private:
    std::string nume;
    std::vector<std::string> termeniCheie;
    int pragIncidente;
    int scorMinim;
    bool activa;
    int fereastraSecunde;

    [[nodiscard]] bool contineCuvantCheie(const std::string& text) const;

public:
    RegulaDetectie(std::string nume_,
                   const std::string& cuvantCheie_,
                   int pragIncidente_,
                   int scorMinim_,
                   bool activa_,
                   int fereastraSecunde_);

    [[nodiscard]] const std::string& getNume() const;
    [[nodiscard]] int getPragIncidente() const;
    [[nodiscard]] bool esteActiva() const;
    [[nodiscard]] int getFereastraSecunde() const;

    [[nodiscard]] bool sePotriveste(const EvenimentSecuritate& ev) const;

    [[nodiscard]] bool operator==(const RegulaDetectie& other) const = default;

    friend std::ostream& operator<<(std::ostream& os, const RegulaDetectie& regula);
};
