#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <cmath>
#include <zip.h>
#include <cstdlib>
#include <atomic>
#include <unistd.h>

std::atomic<bool> found(false);
std::string correct_password = "";
std::atomic<int> passwords_checked(0);
std::mutex output_mutex;

// Passwort-Generierung (lazy): a-zA-Z0-9
void generate_passwords(const std::string& charset, size_t length, size_t start, size_t step, std::vector<std::string>& passwords) {
    size_t num_combinations = std::pow(charset.size(), length);
    for (size_t i = start; i < num_combinations && !found; i += step) {
        std::string password(length, charset[0]);
        size_t temp = i;
        for (size_t j = 0; j < length; ++j) {
            password[j] = charset[temp % charset.size()];
            temp /= charset.size();
        }
        passwords.push_back(password);
    }
}

// Passwort-Check
bool try_password(const std::string& filepath, const std::string& password) {
    int err = 0;
    zip_t* archive = zip_open(filepath.c_str(), ZIP_RDONLY, &err);
    if (!archive) {
        return false;
    }
    zip_set_default_password(archive, password.c_str());
    zip_file_t* file = zip_fopen_index(archive, 0, 0);
    if (file) {
        zip_fclose(file);
        zip_close(archive);
        return true;
    }
    zip_close(archive);
    return false;
}

// Brute-Force-Worker
void brute_force_worker(const std::string& filepath, const std::vector<std::string>& passwords) {
    for (const auto& password : passwords) {
        if (found) return;
        passwords_checked++;
        if (try_password(filepath, password)) {
            std::lock_guard<std::mutex> lock(output_mutex);
            found = true;
            correct_password = password;
            return;
        }
    }
}

// Fortschritt anzeigen
void show_progress(size_t total_passwords) {
    while (!found) {
        {
            std::lock_guard<std::mutex> lock(output_mutex);
            double percent = (double(passwords_checked) / total_passwords) * 100;
            std::cout << "\rChecked: " << passwords_checked
                      << " / " << total_passwords
                      << " (" << percent << "%)"
                      << " Remaining: " << total_passwords - passwords_checked;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

int main(int argc, char* argv[]) {
    std::string filepath;
    size_t num_threads = 1;
    size_t length = 1;
    std::string wordlist_path;
    bool use_wordlist = false;

    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // Argumente parsen
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            filepath = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threads") == 0) {
            num_threads = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--length") == 0) {
            length = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--wordlist") == 0) {
            wordlist_path = argv[++i];
            use_wordlist = true;
        }
    }

    if (filepath.empty()) {
        std::cerr << "Error: No file provided. Use -f or --file to specify the ZIP file.\n";
        return 1;
    }

    // Prüfen, ob die Wordlist genutzt werden soll
    std::vector<std::string> passwords;
    if (use_wordlist) {
        std::ifstream wordlist(wordlist_path);
        if (!wordlist) {
            std::cerr << "Error: Cannot open wordlist file.\n";
            return 1;
        }
        std::string word;
        while (wordlist >> word) {
            passwords.push_back(word);
        }
    } else {
        size_t total_passwords = std::pow(charset.size(), length);
        passwords.resize(total_passwords);
        generate_passwords(charset, length, 0, 1, passwords);
    }

    size_t total_passwords = passwords.size();
    std::cout << "Starting brute-force attack with " << total_passwords << " possible passwords...\n";

    // Threads erstellen
    std::vector<std::thread> threads;
    size_t chunk_size = passwords.size() / num_threads;

    for (size_t i = 0; i < num_threads; ++i) {
        size_t start = i * chunk_size;
        size_t end = (i + 1 == num_threads) ? passwords.size() : (i + 1) * chunk_size;
        threads.emplace_back(brute_force_worker, filepath, std::vector<std::string>(passwords.begin() + start, passwords.begin() + end));
    }

    // Fortschrittsanzeige starten
    std::thread progress_thread(show_progress, total_passwords);

    // Warten, bis alle Threads fertig sind
    for (auto& thread : threads) {
        thread.join();
    }
    progress_thread.join();

    if (found) {
        std::cout << "\nPassword found: " << correct_password << "\n";
    } else {
        std::cout << "\nPassword not found.\n";
    }

    return 0;
}