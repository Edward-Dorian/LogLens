#pragma once

#include <ostream>
#include <string>

enum class Severitate {
    Low,
    Medium,
    High,
    Critical
};

std::ostream& operator<<(std::ostream& os, Severitate severitate);

class AlertaSecuritate {
private:
    std::string tipAmenintare;
    std::string sursaIP;
    Severitate severitate;
    int numarIncidente;
    int scorRisc;
    std::string recomandare;

public:
    AlertaSecuritate(std::string tipAmenintare_,
                     std::string sursaIP_,
                     Severitate severitate_,
                     int numarIncidente_,
                     int scorRisc_,
                     std::string recomandare_);

    [[nodiscard]] Severitate getSeveritate() const;
    [[nodiscard]] int calculeazaPenalizareSanatate() const;
    [[nodiscard]] std::string formateazaPentruSecurityFlow() const;

    [[nodiscard]] bool operator==(const AlertaSecuritate& other) const = default;

    friend std::ostream& operator<<(std::ostream& os, const AlertaSecuritate& alerta);
};
