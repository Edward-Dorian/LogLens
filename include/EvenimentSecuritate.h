#pragma once

#include <ostream>
#include <string>

#include "TimestampLog.h"

class EvenimentSecuritate {
private:
    TimestampLog timestamp;
    std::string sursaIP;
    std::string serviciu;
    int codStatus;
    std::string mesaj;

    [[nodiscard]] bool contineSemnaturaAtac() const;
    [[nodiscard]] bool esteServiciuSensibil() const;

public:
    EvenimentSecuritate(const TimestampLog& timestamp_,
                        std::string sursaIP_,
                        std::string serviciu_,
                        int codStatus_,
                        std::string mesaj_);

    [[nodiscard]] const TimestampLog& getTimestamp() const;
    [[nodiscard]] const std::string& getSursaIP() const;
    [[nodiscard]] const std::string& getServiciu() const;
    [[nodiscard]] const std::string& getMesaj() const;

    [[nodiscard]] int calculeazaScorRisc() const;
    [[nodiscard]] bool esteEroareCritica() const;
    [[nodiscard]] bool esteEroareClient() const;
    [[nodiscard]] bool esteEroareServer() const;

    [[nodiscard]] bool operator==(const EvenimentSecuritate& other) const = default;

    friend std::ostream& operator<<(std::ostream& os, const EvenimentSecuritate& ev);
};
