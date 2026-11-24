#pragma once

#include <optional>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "AlertaSecuritate.h"
#include "ProfilIP.h"
#include "TimestampLog.h"

class RaportSecuritate {
private:
    std::string numeServer;
    std::optional<TimestampLog> inceputInterval;
    std::optional<TimestampLog> sfarsitInterval;
    int scorSanatate;
    int totalEvenimente;
    int numarErori4xx;
    int numarErori5xx;
    std::vector<std::pair<std::string, int>> sumarServicii;
    std::vector<ProfilIP> topProfiluriIP;
    std::vector<AlertaSecuritate> alerte;

    [[nodiscard]] int numaraAlerteCuSeveritate(Severitate severitate) const;

public:
    RaportSecuritate(std::string numeServer_,
                     std::optional<TimestampLog> inceputInterval_,
                     std::optional<TimestampLog> sfarsitInterval_,
                     int scorSanatate_,
                     int totalEvenimente_,
                     int numarErori4xx_,
                     int numarErori5xx_,
                     std::vector<std::pair<std::string, int>> sumarServicii_,
                     std::vector<ProfilIP> topProfiluriIP_,
                     std::vector<AlertaSecuritate> alerte_);

    [[nodiscard]] std::string formateazaJsonComplet() const;

    friend std::ostream& operator<<(std::ostream& os, const RaportSecuritate& raport);
};
