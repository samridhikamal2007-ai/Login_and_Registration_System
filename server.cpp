#if __has_include("crow.h")
#include "crow.h"
#elif __has_include("crow_all.h")
#include "crow_all.h"
#else
#error "Crow header not found. Place crow.h or crow_all.h in the project folder."
#endif
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

class AuthenticationSystem
{
private:
    const std::string dbFilePath = "secure_users_db.txt";
    const std::string globalSalt = "Ex@mpl3_S@lt_2026!";

    static bool fileExists(const std::string &path)
    {
        std::ifstream f(path);
        return f.good();
    }

    std::string hashPassword(const std::string &password, const std::string &username)
    {
        std::hash<std::string> hasher;
        size_t hashValue = hasher(password + globalSalt + username);

        std::stringstream ss;
        ss << std::hex << std::setw(16) << std::setfill('0') << hashValue;
        return ss.str();
    }

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
                return true;
        }
        return false;
    }

    bool isPasswordStrong(const std::string &password)
    {
        // At least 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char (@ $ ! % * ? &)
        const std::regex pattern(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$");
        return std::regex_match(password, pattern);
    }

    bool isValidUsername(const std::string &username)
    {
        const std::regex pattern("^[a-zA-Z0-9]{4,20}$");
        return std::regex_match(username, pattern);
    }

public:
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

    AuthenticationSystem()
    {
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

        std::ofstream dbFile(dbFilePath, std::ios::app);
        if (!dbFile.is_open())
            return AuthStatus::ERR_FILE_IO;

        std::string hashedPassword = hashPassword(password, username);
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
                    return AuthStatus::SUCCESS;
                return AuthStatus::ERR_INVALID_CREDENTIALS;
            }
        }

        return AuthStatus::ERR_USER_NOT_FOUND;
    }
};

static void add_cors_headers(crow::response &res)
{
    res.add_header("Access-Control-Allow-Origin", "* ");
    res.add_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.add_header("Access-Control-Allow-Headers", "Content-Type");
}

int main()
{
    crow::SimpleApp app;
    AuthenticationSystem auth;

    // Serve static files from current directory
    crow::mustache::set_base(".");

    // CORS preflight
    CROW_ROUTE(app, "/api/<path>").methods(crow::HTTPMethod::Options)([](const crow::request &, std::string)
                                                                      {
            crow::response res(204);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res; });

    // Register
    CROW_ROUTE(app, "/api/register").methods(crow::HTTPMethod::Post)([&auth](const crow::request &req)
                                                                     {
        auto json_data = crow::json::load(req.body);
        if (!json_data) return crow::response(400, "{\"message\":\"Invalid JSON\"}");

        std::string username = json_data["username"].s();
        std::string password = json_data["password"].s();

        auto status = auth.registerUser(username, password);

        crow::json::wvalue res;
        using AS = AuthenticationSystem::AuthStatus;

        if (status == AS::SUCCESS) {
            res["message"] = "Registration successful! You can now log in.";
            crow::response r(201);
            r.set_header("Content-Type", "application/json");
            add_cors_headers(r);
            r.body = res.dump();
            return r;
        }
        if (status == AS::ERR_WEAK_PASSWORD) {
            res["message"] = "Password does not meet complexity requirements.";
            crow::response r(400);
            r.set_header("Content-Type", "application/json");
            add_cors_headers(r);
            r.body = res.dump();
            return r;
        }
        if (status == AS::ERR_USER_EXISTS) {
            res["message"] = "Username already taken.";
            crow::response r(409);
            r.set_header("Content-Type", "application/json");
            add_cors_headers(r);
            r.body = res.dump();
            return r;
        }

        res["message"] = "Registration failed due to invalid data.";
        crow::response r(400);
        r.set_header("Content-Type", "application/json");
        add_cors_headers(r);
        r.body = res.dump();
        return r; });

    // Login
    CROW_ROUTE(app, "/api/login").methods(crow::HTTPMethod::Post)([&auth](const crow::request &req)
                                                                  {
        auto json_data = crow::json::load(req.body);
        if (!json_data) return crow::response(400, "{\"message\":\"Invalid JSON\"}");

        std::string username = json_data["username"].s();
        std::string password = json_data["password"].s();

        auto status = auth.loginUser(username, password);

        crow::json::wvalue res;
        using AS = AuthenticationSystem::AuthStatus;

        if (status == AS::SUCCESS) {
            res["message"] = "Login successful! Welcome back.";
            crow::response r(200);
            r.set_header("Content-Type", "application/json");
            add_cors_headers(r);
            r.body = res.dump();
            return r;
        }

        res["message"] = "Invalid username or password.";
        crow::response r(401);
        r.set_header("Content-Type", "application/json");
        add_cors_headers(r);
        r.body = res.dump();
        return r; });

    // Simple route to serve the frontend
    CROW_ROUTE(app, "/").methods(crow::HTTPMethod::Get)([]()
                                                        {
        std::ifstream t("index.html");
        if (!t.is_open()) return crow::response(404);
        std::stringstream buffer;
        buffer << t.rdbuf();
        crow::response res;
        res.code = 200;
        res.set_header("Content-Type", "text/html");
        res.body = buffer.str();
        return res; });

    std::cout << "API Server running on port 8080..." << std::endl;
    app.port(8080).multithreaded().run();
}
