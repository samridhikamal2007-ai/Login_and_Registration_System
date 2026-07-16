// Lightweight backend without Crow.
// Implements:
//  - POST /api/register
//  - POST /api/login
//  - GET  / (serves index.html)
// Uses a minimal HTTP server based on raw WinSock.
//
// Build (MinGW/Dev-C++):
//   g++ server_simple.cpp -O2 -std=gnu++11 -lws2_32 -o server_simple.exe

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")

static std::string readFileToString(const std::string &path)
{
    std::ifstream in(path.c_str(), std::ios::in | std::ios::binary);
    if (!in)
        return "";
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static bool fileExists(const std::string &path)
{
    std::ifstream f(path.c_str());
    return f.good();
}

static std::string trim(const std::string &s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos)
        return "";
    return s.substr(start, end - start + 1);
}

static bool jsonExtractString(const std::string &body, const std::string &key, std::string &out)
{
    // Very small/naive JSON extraction for {"username":"...","password":"..."}
    // Expects double quotes.
    std::string pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
    std::regex re(pattern);
    std::smatch m;
    if (std::regex_search(body, m, re) && m.size() >= 2)
    {
        out = m[1].str();
        return true;
    }
    return false;
}

enum AuthStatus
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
    const std::string globalSalt = "Ex@mpl3_S@lt_2026!";

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
        std::ifstream dbFile(dbFilePath.c_str());
        std::string line;
        while (std::getline(dbFile, line))
        {
            std::stringstream ss(line);
            std::string storedUser;
            std::getline(ss, storedUser, ',');
            if (storedUser == username)
                return true;
        }
        return false;
    }

    bool isPasswordStrong(const std::string &password)
    {
        const std::regex pattern("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$");
        return std::regex_match(password, pattern);
    }

    bool isValidUsername(const std::string &username)
    {
        const std::regex pattern("^[a-zA-Z0-9]{4,20}$");
        return std::regex_match(username, pattern);
    }

public:
    AuthenticationSystem()
    {
        if (!fileExists(dbFilePath))
        {
            std::ofstream dbFile(dbFilePath.c_str());
            dbFile.close();
        }
    }

    AuthStatus registerUser(const std::string &username, const std::string &password)
    {
        if (!isValidUsername(username))
            return ERR_INVALID_USERNAME;
        if (!isPasswordStrong(password))
            return ERR_WEAK_PASSWORD;
        if (isUsernameTaken(username))
            return ERR_USER_EXISTS;

        std::ofstream dbFile(dbFilePath.c_str(), std::ios::app);
        if (!dbFile.is_open())
            return ERR_FILE_IO;

        std::string hashedPassword = hashPassword(password, username);
        dbFile << username << "," << hashedPassword << "\n";
        dbFile.close();
        return SUCCESS;
    }

    AuthStatus loginUser(const std::string &username, const std::string &password)
    {
        if (!fileExists(dbFilePath))
            return ERR_FILE_IO;

        std::ifstream dbFile(dbFilePath.c_str());
        if (!dbFile.is_open())
            return ERR_FILE_IO;

        std::string targetHash = hashPassword(password, username);
        std::string line;
        while (std::getline(dbFile, line))
        {
            std::stringstream ss(line);
            std::string storedUser, storedHash;
            std::getline(ss, storedUser, ',');
            std::getline(ss, storedHash, ',');
            if (storedUser == username)
            {
                if (storedHash == targetHash)
                    return SUCCESS;
                return ERR_INVALID_CREDENTIALS;
            }
        }
        return ERR_USER_NOT_FOUND;
    }
};

static std::string httpResponse(int statusCode, const std::string &statusText,
                                const std::string &body, const std::string &contentType)
{
    std::ostringstream ss;
    ss << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    ss << "Content-Type: " << contentType << "\r\n";
    ss << "Content-Length: " << body.size() << "\r\n";
    ss << "Access-Control-Allow-Origin: *\r\n";
    ss << "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
    ss << "Access-Control-Allow-Headers: Content-Type\r\n";
    ss << "Connection: close\r\n";
    ss << "\r\n";
    ss << body;
    return ss.str();
}

static bool readAllUntilHeaderEnd(SOCKET client, std::string &out)
{
    out.clear();
    char buf[4096];
    // Read a first chunk; for small JSON this is enough.
    int received = recv(client, buf, sizeof(buf), 0);
    if (received <= 0)
        return false;
    out.assign(buf, buf + received);

    // Ensure we have header end
    if (out.find("\r\n\r\n") == std::string::npos)
    {
        // Keep reading until header end or limit
        for (int i = 0; i < 10 && out.find("\r\n\r\n") == std::string::npos; ++i)
        {
            received = recv(client, buf, sizeof(buf), 0);
            if (received <= 0)
                break;
            out.append(buf, buf + received);
        }
    }
    return true;
}

int main()
{
    const int port = 8080;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    SOCKET serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSock == INVALID_SOCKET)
    {
        std::cerr << "socket failed\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr("127.0.0.1");
    service.sin_port = htons((u_short)port);

    if (bind(serverSock, (sockaddr *)&service, sizeof(service)) == SOCKET_ERROR)
    {
        std::cerr << "bind failed (is another server running on 8080?)\n";
        closesocket(serverSock);
        WSACleanup();
        return 1;
    }

    if (listen(serverSock, 10) == SOCKET_ERROR)
    {
        std::cerr << "listen failed\n";
        closesocket(serverSock);
        WSACleanup();
        return 1;
    }

    std::cout << "Simple Auth server running on http://127.0.0.1:" << port << "\n";

    AuthenticationSystem auth;

    while (true)
    {
        sockaddr_in clientAddr;
        int clientLen = sizeof(clientAddr);
        SOCKET clientSock = accept(serverSock, (sockaddr *)&clientAddr, &clientLen);
        if (clientSock == INVALID_SOCKET)
            continue;

        std::string request;
        if (!readAllUntilHeaderEnd(clientSock, request))
        {
            closesocket(clientSock);
            continue;
        }

        // Parse request line: METHOD PATH HTTP/1.1
        std::istringstream reqStream(request);
        std::string method, path, httpver;
        reqStream >> method >> path >> httpver;

        // Extract body (if any)
        std::string body;
        size_t headerEnd = request.find("\r\n\r\n");
        if (headerEnd != std::string::npos)
        {
            body = request.substr(headerEnd + 4);
        }

        // Handle CORS preflight
        if (method == "OPTIONS")
        {
            std::string resp = httpResponse(204, "No Content", "", "text/plain");
            send(clientSock, resp.c_str(), (int)resp.size(), 0);
            closesocket(clientSock);
            continue;
        }

        if (method == "GET" && path == "/")
        {
            std::string html = readFileToString("index.html");
            if (html.empty())
            {
                std::string resp = httpResponse(404, "Not Found", "Not Found", "text/plain");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
            }
            else
            {
                std::string resp = httpResponse(200, "OK", html, "text/html; charset=utf-8");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
            }
            closesocket(clientSock);
            continue;
        }

        if (method == "POST" && path == "/api/register")
        {
            std::string username, password;
            bool okUser = jsonExtractString(body, "username", username);
            bool okPass = jsonExtractString(body, "password", password);

            if (!okUser || !okPass)
            {
                std::string resp = httpResponse(400, "Bad Request",
                                                "{\"message\":\"Invalid JSON\"}", "application/json");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
                closesocket(clientSock);
                continue;
            }

            AuthStatus st = auth.registerUser(username, password);
            if (st == SUCCESS)
            {
                std::string resp = httpResponse(201, "Created",
                                                "{\"message\":\"Registration successful! You can now log in.\"}", "application/json");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
            }
            else if (st == ERR_WEAK_PASSWORD)
            {
                std::string resp = httpResponse(400, "Bad Request",
                                                "{\"message\":\"Password does not meet complexity requirements.\"}", "application/json");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
            }
            else if (st == ERR_USER_EXISTS)
            {
                std::string resp = httpResponse(409, "Conflict",
                                                "{\"message\":\"Username already taken.\"}", "application/json");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
            }
            else if (st == ERR_INVALID_USERNAME)
            {
                std::string resp = httpResponse(400, "Bad Request",
                                                "{\"message\":\"Invalid username.\"}", "application/json");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
            }
            else
            {
                std::string resp = httpResponse(400, "Bad Request",
                                                "{\"message\":\"Registration failed due to invalid data.\"}", "application/json");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
            }

            closesocket(clientSock);
            continue;
        }

        if (method == "POST" && path == "/api/login")
        {
            std::string username, password;
            bool okUser = jsonExtractString(body, "username", username);
            bool okPass = jsonExtractString(body, "password", password);

            if (!okUser || !okPass)
            {
                std::string resp = httpResponse(400, "Bad Request",
                                                "{\"message\":\"Invalid JSON\"}", "application/json");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
                closesocket(clientSock);
                continue;
            }

            AuthStatus st = auth.loginUser(username, password);
            if (st == SUCCESS)
            {
                std::string resp = httpResponse(200, "OK",
                                                "{\"message\":\"Login successful! Welcome back.\"}", "application/json");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
            }
            else
            {
                std::string resp = httpResponse(401, "Unauthorized",
                                                "{\"message\":\"Invalid username or password.\"}", "application/json");
                send(clientSock, resp.c_str(), (int)resp.size(), 0);
            }

            closesocket(clientSock);
            continue;
        }

        // Not found
        {
            std::string resp = httpResponse(404, "Not Found", "Not Found", "text/plain");
            send(clientSock, resp.c_str(), (int)resp.size(), 0);
        }

        closesocket(clientSock);
    }

    closesocket(serverSock);
    WSACleanup();
    return 0;
}
