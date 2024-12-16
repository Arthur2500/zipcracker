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
#include <cstring>

// Globale Stati
std::atomic<size_t> testedPasswords(0);
std::atomic<bool> found(false);

// Signalisiert, dass kein weiteres Passwort mehr nachkommt (Queue bleibt leer)
std::atomic<bool> generationFinished(false);

std::mutex passwordMutex;
std::condition_variable passwordCv;

// Struktur für das Lesen aus einem (gemeinsamen) Speicherpuffer
struct MemoryBuffer {
    const unsigned char* data;
    size_t size;
    size_t pos;
};

// Minizip-Callbacks für das Lesen aus einem MemoryBuffer
voidpf ZCALLBACK mem_open_file_func(voidpf opaque, const char*, int) {
    return opaque; // opaque ist unser MemoryBuffer*
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
    return 0;
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
    MemoryBuffer* mem = static_cast<MemoryBuffer*>(opaque);
    delete mem;
    return 0;
}

int ZCALLBACK mem_error_file_func(voidpf, voidpf) {
    return 0;
}

// Liest die ZIP-Datei komplett in den RAM
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

// Öffnet ein unzFile-Handle, das exklusiv einem Thread gehört
unzFile openThreadLocalHandle(const std::vector<unsigned char>& zipData) {
    zlib_filefunc_def memory_filefunc_def;
    memory_filefunc_def.zopen_file = mem_open_file_func;
    memory_filefunc_def.zread_file = mem_read_file_func;
    memory_filefunc_def.zwrite_file = mem_write_file_func;
    memory_filefunc_def.ztell_file = mem_tell_file_func;
    memory_filefunc_def.zseek_file = mem_seek_file_func;
    memory_filefunc_def.zclose_file = mem_close_file_func;
    memory_filefunc_def.zerror_file = mem_error_file_func;

    // Jeder Thread bekommt ein eigenes MemoryBuffer
    MemoryBuffer* memBuf = new MemoryBuffer;
    memBuf->data = zipData.data();
    memBuf->size = zipData.size();
    memBuf->pos  = 0;

    memory_filefunc_def.opaque = memBuf;
    unzFile uf = unzOpen2((const char*)memBuf, &memory_filefunc_def);
    if (!uf) {
        delete memBuf;
    }
    return uf;
}

// Erkennen der Verschlüsselung (einmalig)
std::string detectZipEncryption(const std::vector<unsigned char>& zipData) {
    unzFile tmp = openThreadLocalHandle(zipData);
    if (!tmp) return "unknown";

    if (unzGoToFirstFile(tmp) != UNZ_OK) {
        unzClose(tmp);
        return "unknown";
    }

    unz_file_info fileInfo;
    char fileName[256];
    if (unzGetCurrentFileInfo(tmp, &fileInfo, fileName, sizeof(fileName), nullptr, 0, nullptr, 0) == UNZ_OK) {
        unzClose(tmp);
        return (fileInfo.compression_method == 99) ? "aes256" : "zipcrypto";
    }
    unzClose(tmp);
    return "unknown";
}

// Passworttest mit thread-lokalem Handle
bool testZipPasswordThreadLocal(unzFile uf, const char* password) {
    // Jedem Thread gehört sein eigenes unzFile -> kein globaler Mutex nötig
    unzCloseCurrentFile(uf);
    if (unzGoToFirstFile(uf) != UNZ_OK) {
        return false;
    }
    if (unzOpenCurrentFilePassword(uf, password) == UNZ_OK) {
        unzCloseCurrentFile(uf);
        return true;
    }
    return false;
}

// Passwort-Generator
void generatePasswords(const std::string& prefix, int length, const std::string& charset,
                       std::queue<std::string>& passwordQueue)
{
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

// Worker-Thread
void bruteForceThread(unzFile threadLocalHandle, std::queue<std::string>& passwordQueue, std::string& result) {
    while (true) {
        if (found.load()) break;

        std::string password;
        {
            std::unique_lock<std::mutex> lock(passwordMutex);
            passwordCv.wait(lock, [&]() {
                // Warte, bis Passwort da, oder 'found' ist true, oder Generation ist fertig und Queue leer
                return found.load() || (!passwordQueue.empty()) || (generationFinished.load() && passwordQueue.empty());
            });

            if (found.load()) break;

            // Falls Queue leer und Generierung fertig --> Abbruch
            if (passwordQueue.empty() && generationFinished.load()) {
                break;
            }
            if (!passwordQueue.empty()) {
                password = passwordQueue.front();
                passwordQueue.pop();
            } else {
                // Noch keine Passwörter in Queue, aber generationFinished ist möglicherweise false => weiter
                continue;
            }
        }

        testedPasswords++;
        if (testZipPasswordThreadLocal(threadLocalHandle, password.c_str())) {
            found.store(true);
            result = password;
            break;
        }
    }
}

// Fortschrittsanzeige
void showProgress(size_t totalPasswords) {
    auto start = std::chrono::steady_clock::now();

    while (true) {
        if (found.load()) break;

        size_t tested = testedPasswords.load();
        bool allTested = (tested >= totalPasswords);

        // Falls wir schon alle durch haben, brechen wir ab:
        if (allTested) break;

        double progress = (totalPasswords == 0)
                          ? 0.0
                          : std::min(100.0, (double)tested / totalPasswords * 100.0);

        auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = now - start;
        double hashrate = (elapsed.count() > 0.0) ? (tested / elapsed.count()) : 0.0;

        double displayhashrate = hashrate;
        std::string hashrateUnit = "H/s";
        if (hashrate >= 1e9) {
            displayhashrate = hashrate / 1e9;
            hashrateUnit = "GH/s";
        } else if (hashrate >= 1e6) {
            displayhashrate = hashrate / 1e6;
            hashrateUnit = "MH/s";
        } else if (hashrate >= 1e3) {
            displayhashrate = hashrate / 1e3;
            hashrateUnit = "kH/s";
        }

        // KORRIGIERTE Formel für Restzeit
        double remainingTime = (hashrate > 0.0)
                               ? (totalPasswords - tested) / hashrate
                               : 0.0;

        if (remainingTime < 0 || std::isinf(remainingTime) || std::isnan(remainingTime)) {
            remainingTime = 0;
        }

        int days    = static_cast<int>(remainingTime / 86400);
        int hours   = static_cast<int>((remainingTime - days * 86400) / 3600);
        int minutes = static_cast<int>((remainingTime - days * 86400 - hours * 3600) / 60);
        int seconds = static_cast<int>(remainingTime - days * 86400 - hours * 3600 - minutes * 60);

        std::cout << "\rFortschritt: " << std::fixed << std::setprecision(2) << progress << "% ("
                  << tested << "/" << totalPasswords << " getestet) "
                  << "Hashrate: " << std::fixed << std::setprecision(2) << displayhashrate << " " << hashrateUnit << " "
                  << "Verbleibende Zeit: " << days << "d " << hours << "h " << minutes << "m " << seconds << "s"
                  << std::flush;

        // 1 Sekunde warten
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Finaler Status
    if (found.load()) {
        std::cout << "\rPasswort gefunden!\n";
    } else {
        std::cout << "\rFortschritt: 100% abgeschlossen. Passwort nicht gefunden.\n";
    }
}

// Anzahl möglicher Passwörter berechnen
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
                    std::cerr << "Fehler: Ungültige Anzahl von Threads!\n";
                    return 1;
                }
                break;
            case 'r':
                recursive = true;
                break;
            default:
                std::cerr << "Verwendung: " << argv[0]
                          << " -f <file> [-l <password-length>] [-w <wordlist>] [-t <thread-count>] [-r]\n";
                return 1;
        }
    }

    if (!file) {
        std::cerr << "Fehler: Bitte -f <file> angeben!\n";
        return 1;
    }

    // ZIP einmal in RAM laden
    std::vector<unsigned char> zipData = loadZipFileToMemory(file);
    if (zipData.empty()) {
        return 1;
    }

    // Verschlüsselungs-Typ ermitteln
    std::string encryptionType = detectZipEncryption(zipData);
    std::cout << "Erkannte Verschlüsselungsmethode: " << encryptionType << std::endl;

    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Queue für Passwörter
    std::queue<std::string> passwordQueue;
    std::string result;
    size_t totalPasswords = 0;

    if (useWordlist) {
        // Wordlist
        std::ifstream wordlist(wordlistPath);
        if (!wordlist) {
            std::cerr << "Fehler: Wordlist konnte nicht geladen werden!\n";
            return 1;
        }
        std::string line;
        while (std::getline(wordlist, line)) {
            passwordQueue.push(line);
        }
        totalPasswords = passwordQueue.size();
        // Hier sind wir mit dem Befüllen "fertig":
        generationFinished.store(true);
    } else {
        // Brute-Force
        totalPasswords = calculateTotalPasswords(passwordLength, charset, recursive);
        // Generator im Hintergrund
        std::thread generatorThread([&]() {
            if (recursive) {
                for (int i = 1; i <= passwordLength; ++i) {
                    generatePasswords("", i, charset, passwordQueue);
                }
            } else {
                generatePasswords("", passwordLength, charset, passwordQueue);
            }
            // Wenn fertig, Signal:
            generationFinished.store(true);
            passwordCv.notify_all();
        });
        generatorThread.detach();
    }

    // Fortschrittsanzeige
    std::thread progressThread([&]() { showProgress(totalPasswords); });

    // Worker-Threads
    std::vector<std::thread> threads;
    threads.reserve(threadCount);
    for (int i = 0; i < threadCount; ++i) {
        unzFile threadLocalHandle = openThreadLocalHandle(zipData);
        if (!threadLocalHandle) {
            std::cerr << "Fehler beim Erstellen eines unzFile-Handles für Thread " << i << "\n";
            continue;
        }
        // Worker-Thread
        threads.emplace_back([&, threadLocalHandle]() {
            bruteForceThread(threadLocalHandle, passwordQueue, result);
            unzClose(threadLocalHandle);
        });
    }

    // Auf alle Worker-Threads warten
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // Fortschrittsanzeige beenden
    progressThread.join();

    if (found) {
        std::cout << "Erfolgreich! Passwort gefunden: " << result << std::endl;
    } else {
        std::cerr << "Passwort konnte nicht gefunden werden!\n";
    }

    return 0;
}