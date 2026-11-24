# LogLens — Analizor de loguri și detector de anomalii

`LogLens` este un utilitar cross-platform de securitate scris în C++23 care încarcă reguli de detecție și loguri de server din fișiere de configurare, validează cronologic timestamp-urile, evaluează scorul de risc al fiecărui eveniment, aplică detecție cu fereastră glisantă (*sliding window*) pe adresă IP, construiește profiluri de reputație IP și generează rapoarte complete (inclusiv export JSON compatibil cu aplicația web de monitorizare SecurityFlow).

### Arhitectura claselor (Tema 1)

Proiectul este organizat modular în `include/` (interfața publică), `src/` (implementare + utilitare interne în `src/internal/`), `app/` (aplicația executabilă), `assets/` (fișiere de date) și `tests/` (teste unitare):

- **`TimestampLog`** (`include/TimestampLog.h`, `src/TimestampLog.cpp`) — moment calendaristic (`an`, `luna`, `zi`, `ora`, `minut`, `secunda`), validat strict la parsare prin `parseazaTimestampLog` (`"YYYY-MM-DD HH:MM:SS"`) și `std::chrono::year_month_day::ok()`, diferență exactă în secunde (`diferentaSecunde`), comparare cronologică (`operator<=>`, `operator==`) și `operator<<`.
- **`EvenimentSecuritate`** (`include/EvenimentSecuritate.h`, `src/EvenimentSecuritate.cpp`) — compune `TimestampLog`, calculează scorul de risc (`0–100`) prin `calculeazaScorRisc()`, clasifică erorile (`esteEroareCritica()`, `esteEroareClient()`, `esteEroareServer()`) și compune `operator<<`.
- **`RegulaDetectie`** (`include/RegulaDetectie.h`, `src/RegulaDetectie.cpp`) — regulă configurabilă (`nume`, `termeniCheie` pre-parsați, `pragIncidente`, `scorMinim`, `activa`, `fereastraSecunde`), potrivire prin `sePotriveste(const EvenimentSecuritate&)`, `operator==` și `operator<<`.
- **`AlertaSecuritate`** și **`enum class Severitate`** (`include/AlertaSecuritate.h`, `src/AlertaSecuritate.cpp`) — alertă generată, calculul penalizării asupra sănătății serverului (`calculeazaPenalizareSanatate()`) și export JSON (`formateazaPentruSecurityFlow()`).
- **`ProfilIP`** și **`enum class NivelReputatie`** (`include/ProfilIP.h`, `src/ProfilIP.cpp`) — agregă activitatea unui IP (`primaActivitate`, `ultimaActivitate`, contoare de risc/erori, servicii distincte), calculează durata activității, scorul mediu/periculozitate și reputația (`Curat`, `Monitorizat`, `Suspect`, `Malitios`).
- **`RaportSecuritate`** (`include/RaportSecuritate.h`, `src/RaportSecuritate.cpp`) — compune sumarul complet al analizei (`std::optional<TimestampLog>`, sănătate server, erori `4xx`/`5xx`, distribuție alerte pe `Severitate`, servicii afectate, top `ProfilIP` și `AlertaSecuritate`), afișare compusă (`operator<<`) și export JSON (`formateazaJsonComplet()`).
- **`MotorLogLens`** (`include/MotorLogLens.h`, `src/MotorLogLens.cpp`) — compune vectori de `EvenimentSecuritate`, `RegulaDetectie` și `AlertaSecuritate`, implementează **Regula celor trei** (constructor de copiere, `operator=` de copiere, destructor), încărcare din fișiere (`assets/reguli.txt`, `assets/server_logs.txt`), detecție *sliding window* (`analizeazaAmenintari`), scor de sănătate, filtrare pe IP, profilare IP și generare raport.

### Folosiți template-ul corespunzător grupei voastre!

| Laborant  | Link template                                |
|-----------|----------------------------------------------|
| Dragoș B  | https://github.com/Ionnier/oop-template      |
| Tiberiu M | https://github.com/MaximTiberiu/oop-template |
| Marius MC | https://github.com/mcmarius/oop-template     |

### Important!

Aveți voie cu agenți care generează cod doar dacă păstrați AGENTS.md și de `.internal/` *pe toată durata semestrului*.
Știm că se poate trișa foarte ușor. Ideea nu este să învățați să trișați mai bine, ci să înțelegeți ce faceți.
Codul generat pus "ca să fie"/pe care nu îl înțelegeți nu se punctează.

Codul din proiect trebuie să poată fi ușor de înțeles și de modificat de către altcineva. Pentru detalii, veniți la ore.

O cerință nu se consideră îndeplinită dacă este realizată doar prin cod generat.

- **Fără cod de umplutură/fără sens!**
- **Fără copy-paste!**
- **Fără variabile globale!**
- **Fără atribute publice!**
- **Fără date în cod!** Datele vor fi citite din fișier, rețea sau bază de date, aveți exemple destule.
- **Obligatoriu** fișiere cu date mai multe din care să citiți, obligatoriu cu biblioteci externe: fișiere (local sau server) sau baze de date
- obligatoriu (TBD) să integrați cel puțin două biblioteci externe pe lângă cele pentru stocare

**NOU!** Livrabile pentru toate temele:
- aplicație
- bibliotecă
- interfața publică pentru bibliotecă

### Tema 0

- [x] Nume proiect (poate fi schimbat ulterior)
- [x] Scurtă descriere a temei alese, ce ne-am propus să implementăm

## Tema 1

#### Cerințe
- [x] definirea a minim **3-4 clase** folosind compunere cu clasele definite de voi; moștenirile nu se iau în considerare aici
- [x] constructori de inițializare cu parametri pentru fiecare clasă
- [x] pentru o aceeași (singură) clasă: constructor de copiere, `operator=` de copiere, destructor
<!-- - [ ] pentru o altă clasă: constructor de mutare, `operator=` de mutare, destructor -->
<!-- - [ ] pentru o altă clasă: toate cele 5 funcții membru speciale -->
- [x] `operator<<` pentru **toate** clasele pentru afișare (`std::ostream`) folosind compunere de apeluri cu `operator<<`
- [x] cât mai multe `const` (unde este cazul) și funcții `private`
- [x] implementarea a minim 3 funcții membru publice pentru funcționalități netriviale specifice temei alese, dintre care cel puțin 1-2 funcții mai complexe
  - nu doar citiri/afișări sau adăugat/șters elemente într-un/dintr-un vector
- [x] scenariu de utilizare **cu sens** a claselor definite:
  - crearea de obiecte și apelarea tuturor funcțiilor membru publice în main
  - vor fi adăugate în fișierul `tastatura.txt` DOAR exemple de date de intrare de la tastatură (dacă există) pentru a acoperi cât mai multe cazuri; dacă aveți nevoie de date din fișiere, creați alte fișiere separat
- [ ] minim 52-60% din codul propriu să fie C++, adică să aveți mai mult cod decât ce e inclus în template; testele nu se pun, nu vă luați după procentajul din interfața web; detalii la ore
- [x] `.gitattributes` configurat corect (nu trebuie făcute modificări aici)
- [ ] tag de `git`: de exemplu `v0.1`
- [ ] serviciu de integrare continuă (CI) cu **toate bifele**; exemplu: GitHub Actions
- [ ] code review #1 2 proiecte

## Tema 2

#### Cerințe
- [ ] separarea codului din clase în `.h` (sau `.hpp`) și `.cpp`
- [ ] moșteniri:
  - minim o clasă de bază și **3 clase derivate** din aceeași ierarhie; cele 3 derivate moștenesc aceeași clasă de bază
  - ierarhia trebuie să fie cu bază proprie, nu derivată dintr-o clasă predefinită
  - [ ] funcții virtuale (pure) apelate prin pointeri de bază din clasa care conține atributul de tip pointer de bază
    - minim o funcție virtuală va fi **specifică temei** (i.e. nu simple citiri/afișări sau preluate din biblioteci i.e. draw/update/render)
    - constructori virtuali (clone): sunt necesari, dar nu se consideră funcții specifice temei
    - afișare virtuală, interfață non-virtuală
  - [ ] apelarea constructorului din clasa de bază din constructori din derivate
  - [ ] clasă cu atribut de tip pointer la o clasă de bază cu derivate; aici apelați funcțiile virtuale prin pointer de bază, eventual prin interfața non-virtuală din bază
    - [ ] suprascris cc/op= pentru copieri/atribuiri corecte, copy and swap
    - [ ] `dynamic_cast`/`std::dynamic_pointer_cast` pentru downcast cu sens
    - [ ] smart pointers (recomandat, opțional)
- [ ] excepții
  - [ ] ierarhie proprie cu baza `std::exception` sau derivată din `std::exception`; minim **3** clase pentru erori specifice distincte
    - clasele de excepții trebuie să trateze categorii de erori distincte (exemplu de erori echivalente: citire fișiere cu diverse extensii)
  - [ ] utilizare cu sens: de exemplu, `throw` în constructor (sau funcție care întoarce un obiect), `try`/`catch` în `main`
  - această ierarhie va fi complet independentă de ierarhia cu funcții virtuale
- [ ] funcții și atribute `static`
- [ ] STL
- [ ] cât mai multe `const`
- [ ] funcții *de nivel înalt*, de eliminat cât mai mulți getters/setters/funcții low-level
- [ ] minim 75-78% din codul propriu să fie C++; testele nu se pun, nu vă luați după procentajul din interfața web
- [ ] la sfârșit: commit separat cu adăugarea unei noi clase derivate fără a modifica restul codului, **pe lângă cele 3 derivate deja adăugate** din aceeași ierarhie
  - noua derivată nu poate fi una existentă care a fost ștearsă și adăugată din nou
  - noua derivată va fi integrată în codul existent (adică va fi folosită, nu adăugată doar ca să fie)
- [ ] tag de `git` pe commit cu **toate bifele**: de exemplu `v0.2`
- [ ] code review #2 2 proiecte

## Tema 3

#### Cerințe
- [ ] 2 șabloane de proiectare (design patterns)
- [ ] o clasă șablon cu sens; minim **2 instanțieri**
  - [ ] preferabil și o funcție șablon (template) cu sens; minim 2 instanțieri
- [ ] minim 80-90% din codul propriu să fie C++; testele nu se pun, nu vă luați după procentajul din interfața web
<!-- - [ ] o specializare pe funcție/clasă șablon -->
- [ ] tag de `git` pe commit cu **toate bifele**: de exemplu `v0.3` sau `v1.0`
- [ ] code review #3 2 proiecte

## Instrucțiuni de compilare

Proiectul este configurat cu CMake.

Instrucțiuni pentru terminal:

1. Pasul de configurare
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
# sau ./scripts/cmake.sh configure
```

Sau pe Windows cu GCC folosind Git Bash:
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -G Ninja
# sau ./scripts/cmake.sh configure -g Ninja
```

Pentru a configura cu ASan, avem opțiunea `-DUSE_ASAN=ON` (nu merge pe Windows cu GCC):
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DUSE_ASAN=ON
# sau ./scripts/cmake.sh configure -e "-DUSE_ASAN=ON"
```


La acest pas putem cere să generăm fișiere de proiect pentru diverse medii de lucru.


2. Pasul de compilare
```sh
cmake --build build --config Debug --parallel 6
# sau ./scripts/cmake.sh build
```

Cu opțiunea `parallel` specificăm numărul de fișiere compilate în paralel.

3. Pasul de testare
```sh
ctest --test-dir build -C Debug --output-on-failure
# sau ./scripts/cmake.sh test
```

Testele sunt **condiție, nu punctaj**: CI verde include și testele. Nu se punctează nici numărul
lor, nici acoperirea (coverage). Testați logica de domeniu din `src/`, prin interfața publică din
`include/`, fără `std::cin` și fără căi absolute. Ce e greu de testat — UI complex, evenimente
aleatoare, un server real — rămâne în `app/` și se verifică prin smoke tests și la demo.

4. Pasul de instalare (opțional)
```sh
cmake --install build --config Debug --prefix install_dir
# sau ./scripts/cmake.sh install
```

Vezi și [`scripts/cmake.sh`](scripts/cmake.sh).

Observație: folderele `build/` și `install_dir/` sunt adăugate în fișierul `.gitignore` deoarece
conțin fișiere generate și nu ne ajută să le versionăm.

## Instrucțiuni pentru a rula executabilul

Există mai multe variante:

1. Din directorul de build (implicit `build`). Executabilul se află la locația `./build/oop_main` după ce a fost rulat pasul de compilare al proiectului (`./scripts/cmake.sh build` - pasul 2 de mai sus).

```sh
./build/oop_main
```

2. Din directorul `install_dir`. Executabilul se află la locația `./install_dir/bin/oop_main` după ce a fost rulat pasul de instalare (`./scripts/cmake.sh install` - pasul 4 de mai sus).

```sh
./install_dir/bin/oop_main
```

3. Rularea programului folosind Valgrind se poate face executând script-ul `./scripts/run_valgrind.sh` din rădăcina proiectului. Pe Windows acest script se poate rula folosind WSL (Windows Subsystem for Linux). Valgrind se poate rula în modul interactiv folosind: `RUN_INTERACTIVE=true ./scripts/run_valgrind.sh`

Implicit, nu se rulează interactiv, iar datele pentru `std::cin` sunt preluate din fișierul `tastatura.txt`.

```sh
RUN_INTERACTIVE=true ./scripts/run_valgrind.sh
# sau
./scripts/run_valgrind.sh
```

Valgrind rulează și testele.

4. Pentru a rula executabilul folosind ASan, este nevoie ca la pasul de configurare (vezi mai sus) să fie activat acest sanitizer. Ar trebui să meargă pe macOS și Linux. Pentru Windows, ar merge doar cu MSVC (nerecomandat).

Comanda este aceeași ca la pasul 1 sau 2. Nu merge combinat cu Valgrind.

```sh
./build/oop_main
./build/oop_test
# sau
./install_dir/bin/oop_main
./install_dir/bin/oop_test
```

## License

The project is licensed under [AGPLv3](LICENSE).

The [template repository](https://github.com/mcmarius/oop-template) itself is licensed under [Unlicense](LICENSE.template).

## Resurse

- Template curs POO (CMake, CI, sanitizers, CTest): https://github.com/mcmarius/oop-template
- Referință C++23 `<chrono>` (`std::chrono::year_month_day`, `std::chrono::sys_days`): https://en.cppreference.com/w/cpp/chrono
- Referință C++20/23 `<compare>` (`operator<=>` și `operator==` defaulted): https://en.cppreference.com/w/cpp/language/default_comparisons
- Specificația JSON (RFC 8259, reguli de escapare string-uri): https://datatracker.ietf.org/doc/html/rfc8259

<!-- oop:guideline-integrity
  2026-11-24 19:34Z AGENTS.md: removed template guidelines (teaching-assistant role, infrastructure freeze, Always in force rules, Do/Don't, and integrity checks) and replaced body with a single custom instruction line
  Append-only record of template-guideline changes. Not a grade; the teacher reads it.
-->
