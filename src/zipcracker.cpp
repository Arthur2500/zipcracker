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

std::atomic<size_t> testedPasswords(0);
std::atomic<bool> found(false);
std::mutex passwordMutex;
std::condition_variable passwordCv;

std::string detectZipEncryption(const char* zipFile) {
    unzFile zip = unzOpen(zipFile);
    if (!zip) return "unknown";
    if (unzGoToFirstFile(zip) != UNZ_OK) {
        unzClose(zip);
        return "unknown";
    }
    unz_file_info fileInfo;
    char fileName[256];
    if (unzGetCurrentFileInfo(zip, &fileInfo, fileName, sizeof(fileName), nullptr, 0, nullptr, 0) == UNZ_OK) {
        if (fileInfo.compression_method == 99) {
            unzClose(zip);
            return "aes256";
        } else {
            unzClose(zip);
            return "zipcrypto";
        }
    }
    unzClose(zip);
    return "unknown";
}

bool testZipPassword(const char* zipFile, const char* password) {
    unzFile zip = unzOpen(zipFile);
    if (!zip) return false;
    if (unzGoToFirstFile(zip) != UNZ_OK) {
        unzClose(zip);
        return false;
    }
    if (unzOpenCurrentFilePassword(zip, password) == UNZ_OK) {
        unzCloseCurrentFile(zip);
        unzClose(zip);
        return true;
    }
    unzClose(zip);
    return false;
}

void generatePasswords(const std::string& prefix, int length, const std::string& charset, std::queue<std::string>& passwordQueue) {
    if (length == 0) {
        std::lock_guard<std::mutex> lock(passwordMutex);
        passwordQueue.push(prefix);
        passwordCv.notify_one();
        return;
    }
    for (char c : charset) {
        generatePasswords(prefix + c, length - 1, charset, passwordQueue);
    }
}

void bruteForce(const char* file, const std::string& encryptionType, std::queue<std::string>& passwordQueue, std::string& result) {
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
        if (testZipPassword(file, password.c_str())) {
            found.store(true);
            result = password;
            break;
        }
    }
}

void showProgress(size_t totalPasswords) {
    auto start = std::chrono::steady_clock::now();
    while (!found.load()) {
        size_t tested = testedPasswords.load();
        double progress = std::min(100.0, (double)tested / totalPasswords * 100.0);
        auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = now - start;
        double hashrate = tested / elapsed.count();
        double remainingTime = (totalPasswords - tested) / hashrate;

        if (remainingTime < 0 || std::isinf(remainingTime) || std::isnan(remainingTime)) {
            remainingTime = 0;
        }

        int days = static_cast<int>(remainingTime / 86400);
        int hours = static_cast<int>((remainingTime - days * 86400) / 3600);
        int minutes = static_cast<int>((remainingTime - days * 86400 - hours * 3600) / 60);
        int seconds = static_cast<int>(remainingTime - days * 86400 - hours * 3600 - minutes * 60);

        std::cout << "\rFortschritt: " << std::fixed << std::setprecision(2) << progress << "% (" << tested << "/" << totalPasswords << " getestet) "
                  << "Hashrate: " << std::fixed << std::setprecision(2) << hashrate << " H/s "
                  << "Verbleibende Zeit: " << days << "d " << hours << "h " << minutes << "m " << seconds << "s" << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    if (found.load()) {
        std::cout << "\rPasswort gefunden!" << std::endl;
    } else {
        std::cout << "\rFortschritt: 100% abgeschlossen. Passwort nicht gefunden." << std::endl;
    }
}

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
    bool recursive = false;
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
                std::cerr << "Verwendung: " << argv[0] << " -f <file> [-l <password-length>] [-w <wordlist>] [-t <thread-count>] [-r]" << std::endl;
                return 1;
        }
    }

    if (!file) {
        std::cerr << "Fehler: Bitte -f <file> angeben!" << std::endl;
        return 1;
    }

    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::queue<std::string> passwordQueue;
    std::string result;
    size_t totalPasswords = 0;
    std::string encryptionType = detectZipEncryption(file);

    if (useWordlist) {
        std::ifstream wordlist(wordlistPath);
        if (!wordlist) {
            std::cerr << "Fehler: Wordlist konnte nicht geladen werden!" << std::endl;
            return 1;
        }
        std::string line;
        while (std::getline(wordlist, line)) {
            passwordQueue.push(line);
        }
        totalPasswords = passwordQueue.size();
    } else {
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

    std::thread progressThread([&]() { showProgress(totalPasswords); });

    std::vector<std::thread> threads;
    for (int i = 0; i < threadCount; ++i) {
        threads.emplace_back([&]() { bruteForce(file, encryptionType, passwordQueue, result); });
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    progressThread.join();

    if (found) {
        std::cout << "Erfolgreich! Passwort gefunden: " << result << std::endl;
    } else {
        std::cerr << "Passwort konnte nicht gefunden werden!" << std::endl;
    }

    return 0;
}