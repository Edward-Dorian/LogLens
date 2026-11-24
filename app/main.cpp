#include <iostream>
#include <vector>

#include "EvenimentSecuritate.h"
#include "MotorLogLens.h"
#include "ProfilIP.h"
#include "RaportSecuritate.h"
#include "RegulaDetectie.h"

int main() {
    MotorLogLens motor{"prod-eu-central-01"};

    const int reguliIncarcate = motor.incarcaReguliDinFisier("assets/reguli.txt");
    const int liniiIncarcate = motor.incarcaLogDinFisier("assets/server_logs.txt");
    if (reguliIncarcate == 0 || liniiIncarcate == 0) {
        std::cerr << "Eroare: nu s-au putut incarca regulile sau fisierul de log.\n";
        return 1;
    }

    motor.analizeazaAmenintari();
    std::cout << motor << "\n";

    const RaportSecuritate raport = motor.genereazaRaportSecuritate();
    std::cout << raport << "\n";

    std::cout << "=== Profiluri IP cu activitate suspecta/malitioasa ===\n";
    for (const ProfilIP& profil : motor.construiesteProfiluriIP()) {
        if (profil.determinaReputatie() != NivelReputatie::Curat) {
            std::cout << "  " << profil << "\n";
        }
    }

    std::cout << "\n=== Investigatie IP atacator (185.220.101.44) ===\n";
    for (const EvenimentSecuritate& ev : motor.extrageEvenimentePerIP("185.220.101.44")) {
        std::cout << "  " << ev << "\n";
    }

    std::cout << "\n=== Export JSON complet SecurityFlow ===\n"
              << raport.formateazaJsonComplet() << "\n\n";

    // Simulare what-if pe o copie a motorului cu o regula stricta pe fereastra scurta (30s).
    MotorLogLens simulareStricta{motor};
    simulareStricta.adaugaRegula(
        RegulaDetectie{"SENSITIVE_ACCOUNT_AUDIT", "admin,root,backup", 2, 40, true, 30});
    simulareStricta.analizeazaAmenintari();

    std::cout << "=== Comparatie productie vs. simulare what-if (fereastra 30s) ===\n"
              << "  Productie -> Alerte: " << motor.getAlerte().size()
              << " | Sanatate: " << motor.calculeazaScorSanatateServer() << "%\n"
              << "  Simulare  -> Alerte: " << simulareStricta.getAlerte().size()
              << " | Sanatate: " << simulareStricta.calculeazaScorSanatateServer() << "%\n"
              << "  Simularea a modificat starea fata de productie: "
              << (simulareStricta != motor ? "DA" : "NU") << "\n\n";

    // Pastrarea unui snapshot independent prin operator= pentru audit ulterior.
    MotorLogLens snapshotAudit{"audit-backup-01"};
    snapshotAudit = motor;
    std::cout << "Snapshot audit sincronizat cu productia: "
              << (snapshotAudit == motor ? "DA" : "NU")
              << " (Alerte: " << snapshotAudit.getAlerte().size()
              << " | Sanatate: " << snapshotAudit.calculeazaScorSanatateServer() << "%)\n";

    return 0;
}
