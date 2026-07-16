#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <sstream>
#include <iomanip>
#include <cctype>

static bool fileExists(const std::string &path)
{
    std::ifstream f(path);
    return f.good();
}

// Enum for standardizing operation results
enum class AuthStatus
{
    SUCCESS,
    ERR_WEAK_PASSWORD,
    ERR_INVALID_USERNAME,
    ERR_USER_EXISTS,
    ERR_USER_NOT_FOUND,
    ERR_INVALID_CREDENTIALS,
    ERR_FILE_IO
};

class AuthenticationSystem
{
private:
    const std::string dbFilePath = "secure_users_db.txt";
    const std::string globalSalt = "Ex@mpl3_S@lt_2026!"; // In production, use dynamic unique salts per user

    // Generates a hex string hash for secure storage (Simulating SHA-256/Bcrypt)
    std::string hashPassword(const std::string &password, const std::string &username)
    {
        std::hash<std::string> hasher;
        // Salting with global salt + username to mitigate rainbow table attacks
        size_t hashValue = hasher(password + globalSalt + username);

        std::stringstream ss;
        ss << std::hex << std::setw(16) << std::setfill('0') << hashValue;
        return ss.str();
    }

    // Checks if the database file contains the username
    bool isUsernameTaken(const std::string &username)
    {
        if (!fileExists(dbFilePath))
            return false;

        std::ifstream dbFile(dbFilePath);
        std::string line, storedUser, storedHash;

        while (std::getline(dbFile, line))
        {
            std::stringstream ss(line);
            std::getline(ss, storedUser, ',');
            if (storedUser == username)
            {
                return true;
            }
        }
        return false;
    }

    // Validates password complexity
    bool isPasswordStrong(const std::string &password)
    {
        // Requires at least 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
        const std::regex pattern(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$");
        return std::regex_match(password, pattern);
    }

    // Validates username formatting
    bool isValidUsername(const std::string &username)
    {
        // Alphanumeric, 4 to 20 characters
        const std::regex pattern("^[a-zA-Z0-9]{4,20}$");
        return std::regex_match(username, pattern);
    }

public:
    AuthenticationSystem()
    {
        // Ensure database file exists
        if (!fileExists(dbFilePath))
        {
            std::ofstream dbFile(dbFilePath);
            dbFile.close();
        }
    }

    AuthStatus registerUser(const std::string &username, const std::string &password)
    {
        if (!isValidUsername(username))
            return AuthStatus::ERR_INVALID_USERNAME;
        if (!isPasswordStrong(password))
            return AuthStatus::ERR_WEAK_PASSWORD;
        if (isUsernameTaken(username))
            return AuthStatus::ERR_USER_EXISTS;

        std::ofstream dbFile(dbFilePath, std::ios::app); // Append mode
        if (!dbFile.is_open())
            return AuthStatus::ERR_FILE_IO;

        std::string hashedPassword = hashPassword(password, username);

        // Storing as CSV format: username,hashed_password
        dbFile << username << "," << hashedPassword << "\n";
        dbFile.close();

        return AuthStatus::SUCCESS;
    }

    AuthStatus loginUser(const std::string &username, const std::string &password)
    {
        if (!fileExists(dbFilePath))
            return AuthStatus::ERR_FILE_IO;

        std::ifstream dbFile(dbFilePath);
        if (!dbFile.is_open())
            return AuthStatus::ERR_FILE_IO;

        std::string line, storedUser, storedHash;
        std::string targetHash = hashPassword(password, username);

        while (std::getline(dbFile, line))
        {
            std::stringstream ss(line);
            std::getline(ss, storedUser, ',');
            std::getline(ss, storedHash, ',');

            if (storedUser == username)
            {
                if (storedHash == targetHash)
                {
                    return AuthStatus::SUCCESS;
                }
                else
                {
                    return AuthStatus::ERR_INVALID_CREDENTIALS;
                }
            }
        }
        return AuthStatus::ERR_USER_NOT_FOUND;
    }
};

void displayMessage(AuthStatus status)
{
    switch (status)
    {
    case AuthStatus::SUCCESS:
        std::cout << "[+] Operation Successful!\n";
        break;
    case AuthStatus::ERR_WEAK_PASSWORD:
        std::cout << "[-] Error: Password must be 8+ chars, with upper, lower, number, and special char.\n";
        break;
    case AuthStatus::ERR_INVALID_USERNAME:
        std::cout << "[-] Error: Username must be 4-20 alphanumeric characters.\n";
        break;
    case AuthStatus::ERR_USER_EXISTS:
        std::cout << "[-] Error: Username is already taken.\n";
        break;
    case AuthStatus::ERR_USER_NOT_FOUND:
        std::cout << "[-] Error: Account does not exist.\n";
        break;
    case AuthStatus::ERR_INVALID_CREDENTIALS:
        std::cout << "[-] Error: Incorrect password.\n";
        break;
    case AuthStatus::ERR_FILE_IO:
        std::cout << "[-] Error: Internal database failure.\n";
        break;
    }
}

int main()
{
    AuthenticationSystem auth;
    int choice;
    std::string username, password;

    while (true)
    {
        std::cout << "\n=== ENTERPRISE AUTH SYSTEM ===\n";
        std::cout << "1. Register\n2. Login\n3. Exit\nSelect option: ";
        if (!(std::cin >> choice))
            break;

        if (choice == 3)
            break;

        std::cout << "Username: ";
        std::cin >> username;
        std::cout << "Password: ";
        std::cin >> password;

        if (choice == 1)
        {
            displayMessage(auth.registerUser(username, password));
        }
        else if (choice == 2)
        {
            displayMessage(auth.loginUser(username, password));
        }
        else
        {
            std::cout << "Invalid choice.\n";
        }
    }

    return 0;
}
