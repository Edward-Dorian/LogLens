#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "AlertaSecuritate.h"
#include "EvenimentSecuritate.h"
#include "MotorLogLens.h"
#include "ProfilIP.h"
#include "RaportSecuritate.h"
#include "RegulaDetectie.h"
#include "TimestampLog.h"

namespace {
std::filesystem::path scrieFisierTemporar(const std::string& nume, const std::string& continut) {
    const std::filesystem::path cale = std::filesystem::temp_directory_path() / nume;
    std::ofstream out(cale);
    out << continut;
    return cale;
}
} // namespace

int main() {
    // 1. TimestampLog: parsare valida/invalida, an bisect, diferenta peste miezul noptii, sortare si operator<<.
    const std::optional<TimestampLog> tsValid = parseazaTimestampLog("2026-03-14 08:05:09");
    assert(tsValid.has_value());
    assert(!parseazaTimestampLog("2026/03/14 08:05:09").has_value());
    assert(!parseazaTimestampLog("2026-13-01 00:00:00").has_value());
    assert(!parseazaTimestampLog("2026-03-14 25:00:00").has_value());
    assert(!parseazaTimestampLog("2026-03-14 08:05").has_value());

    // Validare calendaristica an bisect: 2024-02-29 este valid, 2026-02-29 este invalid.
    assert(parseazaTimestampLog("2024-02-29 12:00:00").has_value());
    assert(!parseazaTimestampLog("2026-02-29 12:00:00").has_value());

    const std::optional<TimestampLog> inainteMiez = parseazaTimestampLog("2026-03-14 23:59:30");
    const std::optional<TimestampLog> dupaMiez = parseazaTimestampLog("2026-03-15 00:00:45");
    assert(inainteMiez.has_value() && dupaMiez.has_value());
    assert(dupaMiez->diferentaSecunde(*inainteMiez) == 75);
    assert(*inainteMiez < *dupaMiez);

    std::vector<TimestampLog> momente = {*dupaMiez, *tsValid, *inainteMiez};
    std::sort(momente.begin(), momente.end());
    assert(momente[0] == *tsValid);
    assert(momente[1] == *inainteMiez);
    assert(momente[2] == *dupaMiez);

    std::ostringstream tsOut;
    tsOut << std::setfill('*') << *tsValid << '|' << std::setw(4) << 7;
    assert(tsOut.str() == "2026-03-14 08:05:09|***7");

    // 2. EvenimentSecuritate: trafic normal (inclusiv pe serviciu sensibil) are risc 0; payload malitios este critic.
    const EvenimentSecuritate evWebOk{*tsValid, "10.0.0.1", "web", 200, "GET /index.html OK"};
    assert(evWebOk.calculeazaScorRisc() == 0);
    assert(!evWebOk.esteEroareCritica());
    assert(!evWebOk.esteEroareClient());
    assert(!evWebOk.esteEroareServer());

    const EvenimentSecuritate evAuthOk{*tsValid, "10.0.0.15", "auth", 200, "User alice authenticated successfully"};
    assert(evAuthOk.calculeazaScorRisc() == 0);

    const EvenimentSecuritate evAtac{
        *tsValid, "45.133.1.92", "web", 403, "Blocked request GET /download?file=../../etc/passwd"};
    assert(evAtac.calculeazaScorRisc() >= 80);
    assert(evAtac.esteEroareCritica());
    assert(evAtac.esteEroareClient());

    const EvenimentSecuritate evServerErr{
        *tsValid, "10.0.5.77", "payments", 500, "Internal server error: exception"};
    assert(evServerErr.esteEroareServer());
    assert(evServerErr.esteEroareCritica());

    // 3. RegulaDetectie si AlertaSecuritate.
    const RegulaDetectie regulaPayload{
        "SUSPICIOUS_PAYLOAD", "../,/etc/passwd,drop table,<script", 1, 60, true, 0};
    const RegulaDetectie regulaInactiva{"INACTIVA", "../etc/passwd", 1, 10, false, 60};
    assert(regulaPayload.sePotriveste(evAtac));
    assert(!regulaPayload.sePotriveste(evWebOk));
    assert(!regulaInactiva.sePotriveste(evAtac));
    assert(regulaPayload.getFereastraSecunde() == 0);

    const AlertaSecuritate alerta{
        "SUSPICIOUS_PAYLOAD", "45.133.1.92", Severitate::Critical, 1, 85, "Blocheaza IP-ul in WAF."};
    assert(alerta.getSeveritate() == Severitate::Critical);
    assert(alerta.calculeazaPenalizareSanatate() == 20);
    const std::string jsonAlerta = alerta.formateazaPentruSecurityFlow();
    assert(jsonAlerta.find(R"("threatType": "SUSPICIOUS_PAYLOAD")") != std::string::npos);
    assert(jsonAlerta.find(R"("severity": "CRITICAL")") != std::string::npos);

    // 4. Respingerea liniilor cu timestamp invalid din log + teste de sliding window (concentrat, rasfirat, neordonat, global).
    const std::filesystem::path fisierInvalid = scrieFisierTemporar(
        "loglens_invalid_ts_test.txt",
        "2026-02-29 10:00:00|1.2.3.4|auth|401|Failed login invalid leap day\n"
        "2026-03-14 10:00:00|1.2.3.4|auth|401|Failed login valid line\n"
        "not-a-timestamp|1.2.3.4|web|200|Ignored\n");
    MotorLogLens motorInvalid{"test-invalid"};
    assert(motorInvalid.incarcaLogDinFisier(fisierInvalid.string()) == 1);
    std::filesystem::remove(fisierInvalid);

    // Atac concentrat in fereastra de 60s (neordonat cronologic) => declanseaza alerta.
    const std::filesystem::path fisierConcentrat = scrieFisierTemporar(
        "loglens_window_concentrat.txt",
        "2026-03-14 10:00:40|198.51.100.9|auth|401|Failed login 3\n"
        "2026-03-14 10:00:10|198.51.100.9|auth|401|Failed login 1\n"
        "2026-03-14 10:00:25|198.51.100.9|auth|401|Failed login 2\n");
    MotorLogLens motorConcentrat{"test-concentrat"};
    motorConcentrat.adaugaRegula(RegulaDetectie{"BRUTE_FORCE", "failed", 3, 50, true, 60});
    assert(motorConcentrat.incarcaLogDinFisier(fisierConcentrat.string()) == 3);
    motorConcentrat.analizeazaAmenintari();
    assert(motorConcentrat.getAlerte().size() == 1);
    std::filesystem::remove(fisierConcentrat);

    // Aceleasi 3 evenimente spatiate la peste 60s => nicio alerta pe fereastra 60s, dar alerta pe fereastra 0 (globala).
    const std::filesystem::path fisierRasfirat = scrieFisierTemporar(
        "loglens_window_rasfirat.txt",
        "2026-03-14 10:00:00|198.51.100.10|auth|401|Failed login 1\n"
        "2026-03-14 10:05:00|198.51.100.10|auth|401|Failed login 2\n"
        "2026-03-14 10:10:00|198.51.100.10|auth|401|Failed login 3\n");
    MotorLogLens motorRasfirat{"test-rasfirat"};
    motorRasfirat.adaugaRegula(RegulaDetectie{"BRUTE_FORCE", "failed", 3, 50, true, 60});
    assert(motorRasfirat.incarcaLogDinFisier(fisierRasfirat.string()) == 3);
    motorRasfirat.analizeazaAmenintari();
    assert(motorRasfirat.getAlerte().empty());

    MotorLogLens motorGlobal{"test-global"};
    motorGlobal.adaugaRegula(RegulaDetectie{"BRUTE_FORCE_GLOBAL", "failed", 3, 50, true, 0});
    assert(motorGlobal.incarcaLogDinFisier(fisierRasfirat.string()) == 3);
    motorGlobal.analizeazaAmenintari();
    assert(motorGlobal.getAlerte().size() == 1);
    std::filesystem::remove(fisierRasfirat);

    // 5. MotorLogLens pe assets/reguli.txt + assets/server_logs.txt (inclusiv IP rasfirat 203.0.113.55 fara alerta falsa).
    MotorLogLens m1{"test-node-01"};
    assert(m1.calculeazaScorSanatateServer() == 100);
    assert(m1.incarcaReguliDinFisier("assets/nu_exista_reguli.txt") == 0);
    assert(m1.incarcaLogDinFisier("assets/nu_exista.txt") == 0);

    // Raport pe motor gol: interval null, 0 evenimente, sanatate 100%.
    const RaportSecuritate raportGol = m1.genereazaRaportSecuritate();
    const std::string jsonGol = raportGol.formateazaJsonComplet();
    assert(jsonGol.find(R"("start": null)") != std::string::npos);
    assert(jsonGol.find(R"("totalEvents": 0)") != std::string::npos);
    assert(jsonGol.find(R"("healthScore": 100)") != std::string::npos);
    std::ostringstream ossRaportGol;
    ossRaportGol << raportGol;
    assert(ossRaportGol.str().find("N/A (fara evenimente)") != std::string::npos);

    assert(m1.incarcaReguliDinFisier("assets/reguli.txt") == 3);
    assert(m1.incarcaLogDinFisier("assets/server_logs.txt") == 29);

    m1.analizeazaAmenintari();
    assert(m1.getAlerte().size() == 4);
    assert(m1.calculeazaScorSanatateServer() < 100);
    assert(m1.extrageEvenimentePerIP("185.220.101.44").size() == 7);

    // 6. ProfilIP: clasificare Curat vs. Malitios, durata activitate, servicii distincte si ordine descrescatoare.
    const std::vector<ProfilIP> profiluri = m1.construiesteProfiluriIP();
    assert(profiluri.size() == 9);
    for (std::size_t i = 1; i < profiluri.size(); ++i) {
        assert(profiluri[i - 1].calculeazaScorPericulozitate() >= profiluri[i].calculeazaScorPericulozitate());
    }

    bool gasitCurat{false};
    bool gasitAtacator{false};
    bool gasitRasfirat{false};
    for (const ProfilIP& profil : profiluri) {
        if (profil.getAdresaIP() == "10.0.0.12") {
            assert(profil.determinaReputatie() == NivelReputatie::Curat);
            assert(profil.calculeazaScorMediuRisc() == 0);
            gasitCurat = true;
        } else if (profil.getAdresaIP() == "185.220.101.44") {
            assert(profil.determinaReputatie() == NivelReputatie::Malitios);
            assert(profil.calculeazaDurataActivitateSecunde() == 38);
            assert(profil.getNumarServiciiAccesate() == 2);
            gasitAtacator = true;
        } else if (profil.getAdresaIP() == "203.0.113.55") {
            assert(profil.getNumarServiciiAccesate() == 3);
            assert(profil.calculeazaDurataActivitateSecunde() == 24600);
            gasitRasfirat = true;
        }
    }
    assert(gasitCurat && gasitAtacator && gasitRasfirat);

    // Invariant ProfilIP: adaugaEveniment ignora evenimentele provenite de la un alt IP.
    ProfilIP profilIzolat{evWebOk};
    profilIzolat.adaugaEveniment(evAtac);
    assert(profilIzolat.getAdresaIP() == "10.0.0.1");
    assert(profilIzolat.calculeazaScorMediuRisc() == 0);
    assert(profilIzolat.determinaReputatie() == NivelReputatie::Curat);
    assert(profilIzolat.getNumarServiciiAccesate() == 1);

    // 7. RaportSecuritate pe motor populat: distributie severitati, servicii afectate, operator<< si JSON complet.
    const RaportSecuritate raport = m1.genereazaRaportSecuritate();
    std::ostringstream ossRaport;
    ossRaport << raport;
    assert(ossRaport.str().find("test-node-01") != std::string::npos);
    assert(ossRaport.str().find("CRITICAL=3, HIGH=1, MEDIUM=0, LOW=0") != std::string::npos);
    assert(ossRaport.str().find("auth:") != std::string::npos);
    assert(ossRaport.str().find("web: 1 evenimente riscante") != std::string::npos);

    const std::string jsonComplet = raport.formateazaJsonComplet();
    assert(jsonComplet.find(R"("serverName": "test-node-01")") != std::string::npos);
    assert(jsonComplet.find(R"("totalEvents": 29)") != std::string::npos);
    assert(jsonComplet.find(R"("4xx": 16)") != std::string::npos);
    assert(jsonComplet.find(R"("5xx": 4)") != std::string::npos);
    assert(jsonComplet.find(R"("critical": 3)") != std::string::npos);
    assert(jsonComplet.find(R"("high": 1)") != std::string::npos);
    assert(jsonComplet.find(R"({ "service": "web", "riskyEvents": 1 })") != std::string::npos);
    assert(jsonComplet.find(R"("threatType": "BRUTE_FORCE")") != std::string::npos);

    // 8. Regula celor trei pe MotorLogLens: constructor de copiere, operator=, auto-atribuire si independenta copiilor.
    MotorLogLens m2{m1};
    assert(m1 == m2);
    m2.adaugaRegula(RegulaDetectie{"EXTRA_RULE", "root", 2, 40, true, 60});
    assert(m1 != m2);

    MotorLogLens m3{"alt-server"};
    m3 = m1;
    assert(m1 == m3);

    MotorLogLens& aliasM3 = m3;
    m3 = aliasM3;
    assert(m1 == m3);

    m3.adaugaRegula(RegulaDetectie{"EXTRA_RULE_2", "admin", 2, 40, true, 60});
    assert(m1 != m3);

    std::ostringstream ossMotor;
    ossMotor << m1;
    assert(ossMotor.str().find("test-node-01") != std::string::npos);
    assert(ossMotor.str().find("BRUTE_FORCE") != std::string::npos);

    return 0;
}
