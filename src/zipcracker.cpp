#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <getopt.h>
#include <minizip/unzip.h>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cstring>  // Für memcpy etc.

// Globale Variablen
std::atomic<size_t> testedPasswords(0);
std::atomic<bool> found(false);
std::mutex passwordMutex;           // Schützt die Passwort-Queue
std::condition_variable passwordCv; // Signalisiert verfügbare Passwörter

// Mutex für die Nutzung des EINEN unzFile-Handles
std::mutex zipHandleMutex;

// Struktur für das Lesen aus einem Speicherpuffer (In-Memory-ZIP)
struct MemoryBuffer {
    const unsigned char* data;
    size_t size;
    size_t pos;
};

// ---- Callback-Funktionen für Minizip (In-Memory) ----
voidpf ZCALLBACK mem_open_file_func(voidpf opaque, const char*, int) {
    // 'opaque' ist unser MemoryBuffer*, wird 1:1 zurückgegeben
    return opaque;
}

uLong ZCALLBACK mem_read_file_func(voidpf opaque, voidpf, void* buf, uLong size) {
    MemoryBuffer* mem = static_cast<MemoryBuffer*>(opaque);
    if (!mem || mem->pos >= mem->size) {
        return 0;
    }
    uLong bytesToRead = (uLong)std::min<size_t>(size, mem->size - mem->pos);
    std::memcpy(buf, mem->data + mem->pos, bytesToRead);
    mem->pos += bytesToRead;
    return bytesToRead;
}

uLong ZCALLBACK mem_write_file_func(voidpf, voidpf, const void*, uLong) {
    return 0; // Wird hier nicht genutzt
}

long ZCALLBACK mem_tell_file_func(voidpf opaque, voidpf) {
    MemoryBuffer* mem = static_cast<MemoryBuffer*>(opaque);
    if (!mem) return -1;
    return static_cast<long>(mem->pos);
}

long ZCALLBACK mem_seek_file_func(voidpf opaque, voidpf, uLong offset, int origin) {
    MemoryBuffer* mem = static_cast<MemoryBuffer*>(opaque);
    if (!mem) return -1;

    size_t newPos = mem->pos;
    switch (origin) {
        case ZLIB_FILEFUNC_SEEK_CUR:
            newPos += offset;
            break;
        case ZLIB_FILEFUNC_SEEK_END:
            newPos = mem->size + offset;
            break;
        case ZLIB_FILEFUNC_SEEK_SET:
            newPos = offset;
            break;
        default:
            return -1;
    }
    if (newPos > mem->size) return -1;
    mem->pos = newPos;
    return 0;
}

int ZCALLBACK mem_close_file_func(voidpf opaque, voidpf) {
    // Wird nur bei unzClose(...) aufgerufen
    MemoryBuffer* mem = static_cast<MemoryBuffer*>(opaque);
    delete mem; // Speicher freigeben
    return 0;
}

int ZCALLBACK mem_error_file_func(voidpf, voidpf) {
    return 0;
}

// Globale (einfache) Funktion, die EIN unzFile-Handle auf unsere ZIP-Daten erstellt.
// Dieses Handle wird später NICHT für jeden Passworttest neu erstellt,
// sondern **nur einmal** wiederverwendet.
unzFile openSingleZipHandle(const std::vector<unsigned char>& zipData) {
    // Callback-Struct vorbereiten
    zlib_filefunc_def memory_filefunc_def;
    memory_filefunc_def.zopen_file = mem_open_file_func;
    memory_filefunc_def.zread_file = mem_read_file_func;
    memory_filefunc_def.zwrite_file = mem_write_file_func;
    memory_filefunc_def.ztell_file = mem_tell_file_func;
    memory_filefunc_def.zseek_file = mem_seek_file_func;
    memory_filefunc_def.zclose_file = mem_close_file_func;
    memory_filefunc_def.zerror_file = mem_error_file_func;

    // MemoryBuffer dynamisch erstellen
    MemoryBuffer* memBuf = new MemoryBuffer;
    memBuf->data = zipData.data();
    memBuf->size = zipData.size();
    memBuf->pos  = 0;

    // "opaque" = unser MemoryBuffer*, das bei unzClose(...) wieder gelöscht wird
    memory_filefunc_def.opaque = memBuf;

    // unzOpen2 erwartet einen Dateinamen, wir übergeben einen Dummy-Cast
    unzFile uf = unzOpen2((const char*)memBuf, &memory_filefunc_def);
    if (!uf) {
        delete memBuf; // bei Fehlschlag wieder freigeben
    }
    return uf;
}

// Liest die ZIP-Datei komplett in den RAM (std::vector<unsigned char>).
std::vector<unsigned char> loadZipFileToMemory(const char* zipFilename) {
    std::ifstream file(zipFilename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "Fehler beim Öffnen der ZIP-Datei." << std::endl;
        return {};
    }
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    if (fileSize <= 0) {
        std::cerr << "Fehler: ZIP-Datei ist leer oder konnte nicht gelesen werden." << std::endl;
        return {};
    }
    std::vector<unsigned char> buffer(static_cast<size_t>(fileSize));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        std::cerr << "Fehler beim Lesen der ZIP-Datei in den Speicher." << std::endl;
        return {};
    }
    return buffer;
}

// Verschlüsselungs-Typ ermitteln. Öffnet und schließt das Handle nur kurz.
std::string detectZipEncryption(const std::vector<unsigned char>& zipData) {
    unzFile tempHandle = openSingleZipHandle(zipData);
    if (!tempHandle) return "unknown";
    if (unzGoToFirstFile(tempHandle) != UNZ_OK) {
        unzClose(tempHandle);
        return "unknown";
    }
    unz_file_info fileInfo;
    char fileName[256];
    if (unzGetCurrentFileInfo(tempHandle, &fileInfo, fileName, sizeof(fileName), nullptr, 0, nullptr, 0) == UNZ_OK) {
        unzClose(tempHandle);
        if (fileInfo.compression_method == 99) {
            return "aes256";
        } else {
            return "zipcrypto";
        }
    }
    unzClose(tempHandle);
    return "unknown";
}

// Einziges Handle, das wiederverwendet wird. Global oder in main halten.
bool testZipPasswordSingleHandle(unzFile zip, const char* password) {
    // Nur ein Thread darf gleichzeitig aufs ZIP zugreifen
    std::lock_guard<std::mutex> lock(zipHandleMutex);

    // MemoryBuffer-Position muss vor jedem Test auf 0 zurückgesetzt werden,
    // sonst sind wir "am Ende" des Buffers.
    // Den einfachsten Trick: wir schließen und öffnen das ZIP neu.
//    <-- ABER: "nur ein einziges unzFile-Handle" heißt, wir wollen NICHT unzClose aufrufen.
//    Wir müssen stattdessen zip->pos = 0 manuell tun.
//    Leider gibt es minizip-intern kein offizielles Reset.
//    ABER wir können unzGoToFirstFile(zip) neu aufrufen.
//    Das Problem: MemoryBuffer->pos ist privat im "opaque".
//    Wir können es re-setzen, indem wir manuell mem_seek_file_func(...) aufrufen
//    oder unzCloseCurrentFile + unzGoToFirstFile.
//
//    Machen wir's so:

    // Wir beenden evtl. offenes File:
    unzCloseCurrentFile(zip);
    // Ganz an den Anfang der ZIP-Struktur gehen
    if (unzGoToFirstFile(zip) != UNZ_OK) {
        return false;
    }

    // Nun Passwort probieren
    if (unzOpenCurrentFilePassword(zip, password) == UNZ_OK) {
        unzCloseCurrentFile(zip);
        return true;
    }
    return false;
}

// ---- Passwort-Generator ----
void generatePasswords(const std::string& prefix, int length, const std::string& charset,
                       std::queue<std::string>& passwordQueue) {
    if (length == 0) {
        {
            std::lock_guard<std::mutex> lock(passwordMutex);
            passwordQueue.push(prefix);
        }
        passwordCv.notify_one();
        return;
    }
    for (char c : charset) {
        generatePasswords(prefix + c, length - 1, charset, passwordQueue);
    }
}

// ---- Brute-Force-Worker ----
void bruteForce(unzFile zipHandle, std::queue<std::string>& passwordQueue, std::string& result) {
    while (!found.load()) {
        std::string password;
        {
            std::unique_lock<std::mutex> lock(passwordMutex);
            passwordCv.wait(lock, [&]() { return !passwordQueue.empty() || found.load(); });
            if (found.load()) break;
            password = passwordQueue.front();
            passwordQueue.pop();
        }
        testedPasswords++;

        if (testZipPasswordSingleHandle(zipHandle, password.c_str())) {
            found.store(true);
            result = password;
            break;
        }
    }
}

// ---- Fortschrittsanzeige ----
void showProgress(size_t totalPasswords) {
    auto start = std::chrono::steady_clock::now();
    while (!found.load()) {
        size_t tested = testedPasswords.load();
        double progress = (totalPasswords == 0)
                          ? 0.0
                          : std::min(100.0, (double)tested / totalPasswords * 100.0);
        auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = now - start;
        double hashrate = tested / (elapsed.count() > 0 ? elapsed.count() : 1.0);
        double remainingTime = (totalPasswords > tested)
                               ? (totalPasswords - tested) / (hashrate > 0 ? hashrate : 1.0)
                               : 0;

        if (remainingTime < 0 || std::isinf(remainingTime) || std::isnan(remainingTime)) {
            remainingTime = 0;
        }

        int days    = static_cast<int>(remainingTime / 86400);
        int hours   = static_cast<int>((remainingTime - days * 86400) / 3600);
        int minutes = static_cast<int>((remainingTime - days * 86400 - hours * 3600) / 60);
        int seconds = static_cast<int>(remainingTime - days * 86400 - hours * 3600 - minutes * 60);

        std::cout << "\rFortschritt: " << std::fixed << std::setprecision(2) << progress << "% ("
                  << tested << "/" << totalPasswords << " getestet) "
                  << "Hashrate: " << std::fixed << std::setprecision(2) << hashrate << " H/s "
                  << "Verbleibende Zeit: " << days << "d " << hours << "h " << minutes << "m " << seconds << "s"
                  << std::flush;

        if (found.load()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    if (found.load()) {
        std::cout << "\rPasswort gefunden!" << std::endl;
    } else {
        std::cout << "\rFortschritt: 100% abgeschlossen. Passwort nicht gefunden." << std::endl;
    }
}

// ---- Anzahl aller möglichen Passwörter ----
size_t calculateTotalPasswords(int length, const std::string& charset, bool recursive) {
    size_t total = 0;
    if (recursive) {
        for (int i = 1; i <= length; ++i) {
            size_t count = 1;
            for (int j = 0; j < i; ++j) {
                count *= charset.size();
            }
            total += count;
        }
    } else {
        size_t count = 1;
        for (int j = 0; j < length; ++j) {
            count *= charset.size();
        }
        total = count;
    }
    return total;
}

int main(int argc, char* argv[]) {
    const char* file = nullptr;
    int passwordLength = 0;
    bool useWordlist = false;
    std::string wordlistPath;
    int threadCount = std::thread::hardware_concurrency();
    bool recursive = false;

    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"length", required_argument, 0, 'l'},
        {"wordlist", required_argument, 0, 'w'},
        {"threads", required_argument, 0, 't'},
        {"recursive", no_argument, 0, 'r'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int opt;
    while ((opt = getopt_long(argc, argv, "f:l:w:t:r", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'f':
                file = optarg;
                break;
            case 'l':
                passwordLength = std::stoi(optarg);
                break;
            case 'w':
                wordlistPath = optarg;
                useWordlist = true;
                break;
            case 't':
                threadCount = std::stoi(optarg);
                if (threadCount <= 0) {
                    std::cerr << "Fehler: Ungültige Anzahl von Threads!" << std::endl;
                    return 1;
                }
                break;
            case 'r':
                recursive = true;
                break;
            default:
                std::cerr << "Verwendung: " << argv[0]
                          << " -f <file> [-l <password-length>] [-w <wordlist>] [-t <thread-count>] [-r]"
                          << std::endl;
                return 1;
        }
    }

    if (!file) {
        std::cerr << "Fehler: Bitte -f <file> angeben!" << std::endl;
        return 1;
    }

    // ZIP-Datei in den Speicher laden
    std::vector<unsigned char> zipData = loadZipFileToMemory(file);
    if (zipData.empty()) {
        return 1;
    }

    // Verschlüsselungs-Typ ermitteln (kurz ein separates Handle öffnen/schließen)
    std::string encryptionType = detectZipEncryption(zipData);
    std::cout << "Erkannte Verschlüsselungsmethode: " << encryptionType << std::endl;

    // Das **einzige** Handle erzeugen und für alle Passwort-Tests wiederverwenden
    unzFile zipHandle = openSingleZipHandle(zipData);
    if (!zipHandle) {
        std::cerr << "Fehler: Konnte kein unzFile-Handle erstellen!" << std::endl;
        return 1;
    }

    // Standard-Charset
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Passwort-Queue
    std::queue<std::string> passwordQueue;
    std::string result;
    size_t totalPasswords = 0;

    if (useWordlist) {
        // Wordlist
        std::ifstream wordlist(wordlistPath);
        if (!wordlist) {
            std::cerr << "Fehler: Wordlist konnte nicht geladen werden!" << std::endl;
            unzClose(zipHandle);
            return 1;
        }
        std::string line;
        while (std::getline(wordlist, line)) {
            passwordQueue.push(line);
        }
        totalPasswords = passwordQueue.size();
    } else {
        // Brute-Force
        totalPasswords = calculateTotalPasswords(passwordLength, charset, recursive);
        std::thread generatorThread([&]() {
            if (recursive) {
                for (int i = 1; i <= passwordLength; ++i) {
                    generatePasswords("", i, charset, passwordQueue);
                }
            } else {
                generatePasswords("", passwordLength, charset, passwordQueue);
            }
        });
        generatorThread.detach();
    }

    // Fortschrittsanzeige in separatem Thread
    std::thread progressThread([&]() { showProgress(totalPasswords); });

    // Brute-Force-Threads
    std::vector<std::thread> threads;
    threads.reserve(threadCount);
    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back([&]() {
            bruteForce(zipHandle, passwordQueue, result);
        });
    }

    // Threads joinen
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    // Fortschrittsanzeige abschließen
    progressThread.join();

    // Handle am Ende schließen -> ruft mem_close_file_func auf und löscht MemoryBuffer
    unzClose(zipHandle);

    if (found) {
        std::cout << "Erfolgreich! Passwort gefunden: " << result << std::endl;
    } else {
        std::cerr << "Passwort konnte nicht gefunden werden!" << std::endl;
    }

    return 0;
}