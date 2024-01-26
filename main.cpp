#include <iostream>
#include <fstream>
#include <filesystem>
#include <stdio.h>
#include <map>
#include <thread>

#define ASIO_STANDALONE
#include <asio.hpp>

#include <sqlite3.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using asio::ip::tcp;

// sqlite3 functions
static int callback(void* data, int argc, char** argv, char** azColName);

// application functions
bool register_user(tcp::socket& socket_, std::string& email, std::string& username, std::string& password, std::string& key);
std::string login_user(tcp::socket& socket_, std::string& email, std::string& password);
void recover_user(tcp::socket& socket_, std::string& email);
void alter_username(tcp::socket& socket_, std::string& old_username, std::string& new_username);
void alter_password(tcp::socket& socket_, std::string& old_password, std::string& new_password);
void delete_user(tcp::socket& socket_, std::string& email, std::string& password);
void sync_chat(tcp::socket& socket_, std::string& username, std::string& contents, tcp::socket& recipient_socket_, bool is_online, RSA* sender_key, RSA* recipient_key);
void retrieve_chat(tcp::socket& socket_, std::string& username, RSA* key);
void add_connection(tcp::socket& socket_, std::string& username, std::string& connection_username, RSA* sender_key, bool is_online, tcp::socket& recipient_socket_, RSA* recipient_key);

void send_response(tcp::socket& socket, std::string& response);

void encrypt(std::string& str, RSA* key);
void decrypt(std::string& str);

RSA* private_key = nullptr;

std::string delimeter = "<eos>";

class TCPServer
{
public:
    TCPServer(asio::io_context& io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port))
    {
        if (!std::filesystem::exists("../db"))
        {
            create_db();
        }
        if (!std::filesystem::exists("../db/public.pem") && !std::filesystem::exists("../db/private.pem"))
        {
            generate_keys();
        }

        read_keys();

        std::cout << "Listening...\n";
        start_accept();

        // std::thread check_connected_thread([this] { check_connected(); });
        // check_connected_thread.detach();
    }
private:
    void start_accept()
    {
        auto socket_ = std::make_shared<tcp::socket>(acceptor_.get_executor());

        acceptor_.async_accept(*socket_, [this, socket_](std::error_code ec) {
            if (!ec)
            {
                std::cout << "Connection established!\n";
                handle_request(std::move(socket_));
            }

            start_accept();
        });
    }

    void handle_request(std::shared_ptr<tcp::socket> socket_)
    {
        if (socket_->is_open())
        {
            auto receive_buffer_ = std::make_shared<asio::streambuf>();

            asio::async_read_until(*socket_, *receive_buffer_, delimeter,
                [this, socket_, receive_buffer_](std::error_code ec, std::size_t bytes){
                    if (!ec)
                    {
                        std::istream input_stream(receive_buffer_.get());
                        std::string request_size_str;
                        std::getline(input_stream, request_size_str);

                        request_size_str = request_size_str.substr(0, request_size_str.find(delimeter));

                        int request_size = std::stoi(request_size_str);

                        std::shared_ptr<std::string> request = std::make_shared<std::string>();

                        request->clear();
                        request->resize(request_size);

                        asio::async_read(*socket_, asio::buffer(request->data(), request_size),
                            [this, socket_, request](std::error_code ec, std::size_t bytes){
                                if (!ec)
                                {
                                    if (!(*request).empty())
                                    {
                                        handle_command(std::move(socket_), *request);
                                    }
                                }
                                else
                                {
                                    std::cerr << "Error reading request: " << ec.message() << '\n';
                                }

                            });
                   }
                   else
                   {
                       std::cerr << "Error reading request size: " << ec.message() << '\n';
                   }

                    handle_request(std::move(socket_));
                });
        }
        else
        {
            std::cerr << "Socket is closed.\n";
        }
    }

    void handle_command(std::shared_ptr<tcp::socket> socket_, std::string& command)
    {
        if (command == "key")
        {
            std::cout << command << '\n';

            std::string response = "key-" + public_key_str;
            send_response(*socket_, response);

            return;
        }

        decrypt(command);
        std::cout << command << '\n';

        if (command.empty())
        {
            std::cout << "Command is empty.\n";
            return;
        }

        std::vector<std::string> tokens;
        std::string token;
        std::stringstream line(command);

        while(std::getline(line, token, ' '))
        {
            if (token == "sync")  // sync sender_username recipient_username|destination|date_time|message
            {
                std::getline(line, token, ' ');
                tokens.push_back(token);

                std::getline(line, token, '\0');
                tokens.push_back(token);

                if (connections_.find(token.substr(0, token.find('|'))) != connections_.end())
                {
                    sync_chat(*connections_[tokens[0]], tokens[0], tokens[1],
                              *connections_[token.substr(0, token.find('|'))],
                              true, public_keys[tokens[0]],
                              public_keys[token.substr(0, token.find('|'))]);
                }
                else
                {
                    sync_chat(*connections_[tokens[0]], tokens[0], tokens[1],
                              *socket_, false, public_keys[tokens[0]], nullptr);
                }

                break;
            }
            else if (token == "register")
            {
                std::getline(line, token, ' '); // username
                tokens.push_back(token);

                std::getline(line, token, ' '); // email
                tokens.push_back(token);

                std::getline(line, token, ' '); // password
                tokens.push_back(token);

                std::getline(line, token, '\0'); // public_key
                tokens.push_back(token);

                bool is_registered = register_user(*socket_, tokens[0], tokens[1], tokens[2], tokens[3]);

                if (is_registered)
                {
                    if (connections_.find(tokens[0]) == connections_.end())
                        connections_[tokens[0]] = socket_;

                    BIO* bio_public = BIO_new_file(("../db/" + tokens[0] + "/public.pem").c_str(), "rb");
                    if (!bio_public)
                    {
                        std::cerr << "Error opening " << ("../db/" + tokens[0] + "/public.pem") << " file.\n";
                    }
                    else
                    {
                        if (public_keys.find(tokens[0]) == public_keys.end())
                            public_keys[tokens[0]] = PEM_read_bio_RSAPublicKey(bio_public, nullptr, nullptr, nullptr);
                    }

                    BIO_free(bio_public);
                }

                break;
            }

            tokens.push_back(token);
        }

        if (tokens[0] == "exit") // tokens[1] is username
        {
            connections_.erase(tokens[1]);
            public_keys.erase(tokens[1]);
            socket_->close();
        }

        if (tokens[0] == "login") // login email password
        {
            std::string username = login_user(*socket_, tokens[1], tokens[2]);

            if (username != "0")
            {
                connections_[username] = socket_;

                BIO* bio_public = BIO_new_file(("../db/" + username + "/public.pem").c_str(), "rb");
                if (!bio_public)
                {
                    std::cerr << "Error opening " << ("../db/" + username + "/public.pem") << " file.\n";
                }
                else
                {
                    public_keys[username] = PEM_read_bio_RSAPublicKey(bio_public, nullptr, nullptr, nullptr);
                }

                BIO_free(bio_public);
            }
        }
        else if (tokens[0] == "recover") // recover email
        {
            recover_user(*socket_, tokens[1]);
        }
        else if (tokens[0] == "alter_username") // alter_username user_id old_username new_username
        {
            alter_username(*(connections_[tokens[1]]), tokens[2], tokens[3]);
        }
        else if (tokens[0] == "alter_password") // alter_password user_id old_password new_password
        {
            alter_password(*(connections_[tokens[1]]), tokens[2], tokens[3]);
        }
        else if (tokens[0] == "delete") // delete user_id email password
        {
            delete_user(*(connections_[tokens[1]]), tokens[2], tokens[3]);
        }
        else if (tokens[0] == "retrieve") // retrieve user_id
        {
            retrieve_chat(*(connections_[tokens[1]]), tokens[1], public_keys[tokens[1]]);
        }
        else if (tokens[0] == "connect") // connect username connection_username
        {
            if (connections_.find(tokens[2]) != connections_.end() && public_keys.find(tokens[2]) != public_keys.end())
                add_connection(*(connections_[tokens[1]]), tokens[1], tokens[2], public_keys[tokens[1]], true, *(connections_[tokens[2]]), public_keys[tokens[2]]);
            else
                add_connection(*(connections_[tokens[1]]), tokens[1], tokens[2], public_keys[tokens[1]], false, *(connections_[tokens[1]]), public_keys[tokens[1]]);
        }

        tokens.clear();
    }

    void create_db()
    {
        std::filesystem::create_directory("../db");

        char* error_message = 0;
        sqlite3* accounts_db;
        int rc = sqlite3_open("../db/accounts.db", &accounts_db);

        if (rc != SQLITE_OK)
        {
            std::cout << "Error creating an accounts database: " << sqlite3_errmsg(accounts_db) << '\n';

            sqlite3_close(accounts_db);
            return;
        }

        std::string sql = "create table users(username text unique, email text unique, password text);";
        rc = sqlite3_exec(accounts_db, sql.c_str(), callback, 0, &error_message);

        if (rc != SQLITE_OK)
        {
            std::cout << "Error creating an accounts database: " << error_message << '\n';

            sqlite3_free(error_message);
            sqlite3_close(accounts_db);
            return;
        }

        sqlite3_free(error_message);
        sqlite3_close(accounts_db);
    }

    void generate_keys()
    {
        int bits = 2048;
        unsigned long e = RSA_F4;

        RSA* rsa = RSA_new();

        BIGNUM* bne = BN_new();
        BN_set_word(bne, e);
        RSA_generate_key_ex(rsa, bits, bne, NULL);

        FILE* privKeyFile = fopen("../db/private.pem", "wb");
        PEM_write_RSAPrivateKey(privKeyFile, rsa, NULL, NULL, 0, NULL, NULL);
        fclose(privKeyFile);

        FILE* pubKeyFile = fopen("../db/public.pem", "wb");
        PEM_write_RSAPublicKey(pubKeyFile, rsa);
        fclose(pubKeyFile);

        RSA_free(rsa);
        BN_free(bne);
    }

    void read_keys()
    {
        FILE* private_key_file = fopen("../db/private.pem", "rb");
        private_key = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
        fclose(private_key_file);

        std::ifstream file("../db/public.pem");

        if (!file.is_open())
        {
            std::cerr << "Error opening file.\n";
            return;
        }

        std::string line;
        while (std::getline(file, line))
        {
            public_key_str += line;

            if (line == "-----END RSA PUBLIC KEY-----")
                break;

            public_key_str += "|";
        }

        file.close();
    }

    void check_connected()
    {
        while (true)
        {
            std::cout << "Checking connected.\n";
            for (const auto& [k, v] : connections_)
            {
                if (!(*v).is_open())
                {
                    connections_.erase(k);
                    public_keys.erase(k);

                    std::cout << k << " has exited.\n";
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    }

    tcp::acceptor acceptor_;
    std::map<std::string, std::shared_ptr<tcp::socket>> connections_;
    std::map<std::string, RSA*> public_keys;
    std::string public_key_str = "";
};

int main()
{
    try
    {
        asio::io_context io_context;
        TCPServer server(io_context, 8888);

        io_context.run();
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}

bool register_user(tcp::socket& socket_, std::string& username, std::string& email, std::string& password, std::string& key)
{
    std::stringstream line(key);
    std::string token;

    key = "";
    while(std::getline(line, token, '|'))
    {
        key += token;

        if (token == "-----END RSA PUBLIC KEY-----")
            break;

        key += "\n";
    }

    RSA* temp_key = nullptr;
    BIO* bio = BIO_new_mem_buf(key.c_str(), -1);

    std::string response = "";

    if (bio == nullptr)
    {
        RSA_free(temp_key);
        BIO_free(bio);
        std::cout << "Error reading public key.\n";
        return false;
    }

    temp_key = PEM_read_bio_RSA_PUBKEY(bio, &temp_key, NULL, NULL);

    BIO_free(bio);

    sqlite3* accounts_db;
    int rc = sqlite3_open("../db/accounts.db", &accounts_db);

    if (rc)
    {
        std::cout << "Registration error: " << sqlite3_errmsg(accounts_db) << '\n';

        response = "re.";
        send_response(socket_, response);

        sqlite3_close(accounts_db);
        RSA_free(temp_key);

        return false;
    }

    char* error_message = 0;
    std::string sql = "insert into users values(\"" +
                      username + "\", \"" +
                      email + "\", \"" +
                      password + "\");";

    sqlite3_exec(accounts_db, sql.c_str(), callback, 0, &error_message);

    if (rc != SQLITE_OK && std::strcmp(error_message, "UNIQUE constraint failed: users.username") == 0)
    {
        std::cout << "Registration error: account with this username already exists.\n";

        response = "e:awtuae.tdu.";
        send_response(socket_, response);

        sqlite3_free(error_message);
        sqlite3_close(accounts_db);
        RSA_free(temp_key);

        return false;
    }
    else if (rc != SQLITE_OK && std::strcmp(error_message, "UNIQUE constraint failed: users.email") == 0)
    {
        std::cout << "Registration error: account with this email address already exists.\n";

        response = "e:awteaae.tli.";
        send_response(socket_, response);

        sqlite3_free(error_message);
        sqlite3_close(accounts_db);
        RSA_free(temp_key);

        return false;
    }

    if (!std::filesystem::exists("../db/" + username))
    {
        std::filesystem::create_directory("../db/" + username);

        // create history database
        sqlite3* history_db;
        rc = sqlite3_open(("../db/" + username + "/history.db").c_str(), &history_db);

        if (rc != SQLITE_OK)
        {
            std::cout << "Registration error: " << sqlite3_errmsg(history_db) << '\n';

            response = "re.";
            send_response(socket_, response);

            sqlite3_close(history_db);
            RSA_free(temp_key);

            return false;
        }

        sql = "create table history(recipient_username text, destination text, date_time text, message text);";
        rc = sqlite3_exec(history_db, sql.c_str(), callback, 0, &error_message);

        if (rc != SQLITE_OK)
        {
            std::cout << "Registration error:" << error_message << '\n';

            response = "re.";
            send_response(socket_, response);

            sqlite3_free(error_message);
            sqlite3_close(history_db);
            RSA_free(temp_key);

            return false;
        }

        // create connections database
        sqlite3* connections_db;
        rc = sqlite3_open(("../db/" + username + "/connections.db").c_str(), &connections_db);

        if (rc != SQLITE_OK)
        {
            std::cout << "Registration error: " << sqlite3_errmsg(connections_db) << '\n';

            response = "re.";
            send_response(socket_, response);

            sqlite3_close(connections_db);
            RSA_free(temp_key);

            return false;
        }

        sql = "create table connections(username text unique);";
        rc = sqlite3_exec(connections_db, sql.c_str(), callback, 0, &error_message);

        if (rc != SQLITE_OK)
        {
            std::cout << "Registration error:" << error_message << '\n';

            response = "re.";
            send_response(socket_, response);

            sqlite3_free(error_message);
            sqlite3_close(connections_db);
            RSA_free(temp_key);

            return false;
        }

        FILE* publicKeyFile = fopen(("../db/" + username + "/public.pem").c_str(), "wb");
        fwrite(key.c_str(), 1, key.length(), publicKeyFile);
        fclose(publicKeyFile);

        response = "wa.";
        send_response(socket_, response);

        sqlite3_close(history_db);
        sqlite3_close(connections_db);
        RSA_free(temp_key);
    }

    sqlite3_free(error_message);
    sqlite3_close(accounts_db);

    return true;
}

std::string login_user(tcp::socket& socket_, std::string& username, std::string& password)
{
    std::string response = "";

    sqlite3* accounts_db;
    int rc = sqlite3_open("../db/accounts.db", &accounts_db);

    if (rc)
    {
        std::cout << "Login error: " << sqlite3_errmsg(accounts_db) << '\n';

        response = "le.";
        send_response(socket_, response);

        sqlite3_close(accounts_db);

        return "0";
    }

    sqlite3_stmt* statement;
    std::string sql = "select username from users where username=\"" + username +
                      "\" and password=\"" + password + "\";";

    rc = sqlite3_prepare_v2(accounts_db, sql.c_str(), -1, &statement, NULL);

    if (rc != SQLITE_OK)
    {
        std::cout << "Login error: " << sqlite3_errmsg(accounts_db) << '\n';

        response = "le.";
        send_response(socket_, response);

        sqlite3_close(accounts_db);
        sqlite3_finalize(statement);

        return "0";
    }

    sqlite3_bind_int(statement, 1, 1);

    rc = sqlite3_step(statement);

    if (rc == SQLITE_ROW)
    {
        sqlite3_finalize(statement);
        sqlite3_close(accounts_db);

        response = "wa.";
        send_response(socket_, response);

        return username;
    }
    else
    {
        std::cout << "No account with such username and/or password.\n";

        response = "nawsua/op.";
        send_response(socket_, response);

        sqlite3_close(accounts_db);
        sqlite3_finalize(statement);

        return "0";
    }

    return "0";
}

void encrypt(std::string& str, RSA* key)
{
    const int chunk_size = 240;
    const int rsa_len = RSA_size(key);

    std::string encrypted_string;

    for (int i = 0; i < str.length(); i += chunk_size)
    {
        int remaining = std::min(chunk_size, static_cast<int>(str.length() - i));
        std::vector<unsigned char> encrypted_text(rsa_len);

        int encrypt_size = RSA_public_encrypt(remaining,
                                              reinterpret_cast<const unsigned char*>(str.substr(i, remaining).c_str()),
                                              encrypted_text.data(), key, RSA_PKCS1_PADDING);

        if (encrypt_size == -1) {
            std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), NULL) << '\n';
            encrypted_string = "";

            break;
        }
        else
        {
            encrypted_string += std::string(reinterpret_cast<char*>(encrypted_text.data()), encrypt_size);
        }
    }

    str = encrypted_string;
}

void decrypt(std::string& str)
{
    const int chunk_size = 256;
    const int rsa_len = RSA_size(private_key);

    std::string decrypted_string;

    for (int i = 0; i < str.length(); i += chunk_size)
    {
        int remaining = std::min(chunk_size, static_cast<int>(str.length() - i));
        std::vector<unsigned char> decrypted_text(rsa_len);

        int decrypt_size = RSA_private_decrypt(remaining,
                                               reinterpret_cast<const unsigned char*>(str.substr(i, remaining).c_str()),
                                               decrypted_text.data(), private_key, RSA_PKCS1_PADDING);

        if (decrypt_size == -1)
        {
            std::cerr << "Decryption failed: " << ERR_error_string(ERR_get_error(), NULL) << '\n';
            decrypted_string = "";

            break;
        }
        else
        {
            decrypted_string += std::string(reinterpret_cast<char*>(decrypted_text.data()), decrypt_size);
        }
    }

    str = decrypted_string;
}

void recover_user(tcp::socket& socket_, std::string& email)
{
    // IN PROCESS...
}

void alter_username(tcp::socket& socket_, std::string& old_username, std::string& new_username)
{
    // IN PROCESS...
}

void alter_password(tcp::socket& socket_, std::string& old_password, std::string& new_password)
{
    // IN PROCESS...
}

void delete_user(tcp::socket& socket_, std::string& email, std::string& password)
{
    // IN PROCESS...
}

void sync_chat(tcp::socket& socket_, std::string& username, std::string& contents, tcp::socket& recipient_socket_, bool is_online, RSA* sender_key, RSA* recipient_key)
{
    std::string response = "";

    std::vector<std::string> tokens; // recipient_username|destination|date_time|message
    std::string token;
    std::stringstream line(contents);

    std::getline(line, token, '|');
    tokens.push_back(token);

    std::getline(line, token, '|');
    tokens.push_back(token);

    std::getline(line, token, '|');
    tokens.push_back(token);

    std::getline(line, token, '\0');
    tokens.push_back(token);

    // sync sender
    sqlite3* history_db;
    int rc = sqlite3_open(("../db/" + username + "/history.db").c_str(), &history_db);

    if (rc)
    {
        std::cout << "Sync error: " << sqlite3_errmsg(history_db) << '\n';

        response = "se.";
        encrypt(response, sender_key);
        send_response(socket_, response);

        sqlite3_close(history_db);

        return;
    }

    char* error_message = 0;
    std::string sql = "insert into history values(\"" +
                      tokens[0] + "\", \"" +  // recipient_username
                      tokens[1] + "\", \"" +  // destination
                      tokens[2] + "\", \"" +  // date_time
                      tokens[3] + "\");"; // message

    sqlite3_exec(history_db, sql.c_str(), callback, 0, &error_message);

    if (rc != SQLITE_OK)
    {
        std::cout << "Sync error: " << error_message << '\n';

        response = "se.";
        encrypt(response, sender_key);
        send_response(socket_, response);

        sqlite3_free(error_message);
        sqlite3_close(history_db);

        return;
    }

    response = "sync-" + tokens[0] + "|out|" + tokens[2] + "|" + tokens[3];
    encrypt(response, sender_key);

    // send response to sender
    send_response(socket_, response);

    // sync recipient
    rc = sqlite3_open(("../db/" + tokens[0] + "/history.db").c_str(), &history_db);

    if (rc)
    {
        std::cout << "Sync error: " << sqlite3_errmsg(history_db) << '\n';

        if (is_online)
        {
            response = "se.";
            encrypt(response, recipient_key);
            send_response(recipient_socket_, response);
        }

        sqlite3_close(history_db);

        return;
    }

    sql = "insert into history values(\"" +
          username +  // recipient_username
          "\", \"in\", \"" +  // destination
          tokens[2] + "\", \"" + // date_time
          tokens[3] + "\");";  // message

    sqlite3_exec(history_db, sql.c_str(), callback, 0, &error_message);

    if (rc != SQLITE_OK)
    {
        std::cout << "Sync error: " << error_message << '\n';

        if (is_online)
        {
            response = "se.";
            encrypt(response, recipient_key);
            send_response(recipient_socket_, response);
        }

        sqlite3_free(error_message);
        sqlite3_close(history_db);

        return;
    }

    sqlite3_close(history_db);

    if (is_online)
    {
        // send message to recipient
        response = "sync-" + username + "|in|" + tokens[2] + "|" + tokens[3];
        encrypt(response, recipient_key);
        send_response(recipient_socket_, response);
    }
}

void retrieve_chat(tcp::socket& socket_, std::string& username, RSA* key)
{
    std::string response = "";
    std::vector<std::string> history;

    sqlite3* history_db;
    int rc = sqlite3_open(("../db/" + username + "/history.db").c_str(), &history_db);

    if (rc)
    {
        std::cout << "Could not connect to a database: " << sqlite3_errmsg(history_db) << '\n';

        response = "re.";
        encrypt(response, key);
        send_response(socket_, response);

        sqlite3_close(history_db);

        return;
    }

    sqlite3_stmt* statement;
    std::string sql = "select recipient_username, destination, date_time, message from history;";

    rc = sqlite3_prepare_v2(history_db, sql.c_str(), -1, &statement, NULL);

    if (rc != SQLITE_OK)
    {
        std::cout << "Retrieve error: " << sqlite3_errmsg(history_db) << '\n';

        response = "re.";
        encrypt(response, key);
        send_response(socket_, response);

        sqlite3_close(history_db);
        sqlite3_finalize(statement);

        return;
    }

    sqlite3_bind_int(statement, 1, 1);

    std::string line;
    while ((rc = sqlite3_step(statement)) == SQLITE_ROW)
    {
        line.clear();
        line = "retrieve_history-" + std::string((const char *) sqlite3_column_text(statement, 0)) + "|" +
               std::string((const char *) sqlite3_column_text(statement, 1)) + "|" +
               std::string((const char *) sqlite3_column_text(statement, 2)) + "|" +
               std::string((const char *) sqlite3_column_text(statement, 3));
        encrypt(line, key);
        history.push_back(line);
    }

    if (rc != SQLITE_DONE)
    {
        std::cout << "Retrieve error: " << sqlite3_errmsg(history_db) << '\n';

        response = "re.";
        encrypt(response, key);
        send_response(socket_, response);

        sqlite3_close(history_db);
        sqlite3_finalize(statement);

        return;
    }

    sqlite3_finalize(statement);
    sqlite3_close(history_db);

    if (!history.empty())
    {
        for (std::string& line: history)
        {

            send_response(socket_, line);

            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    // send connections
    history.clear();

    rc = sqlite3_open(("../db/" + username + "/connections.db").c_str(), &history_db);

    if (rc)
    {
        std::cout << "Could not connect to a database: " << sqlite3_errmsg(history_db) << '\n';

        response = "re.";
        encrypt(response, key);
        send_response(socket_, response);

        sqlite3_close(history_db);

        return;
    }

    sql = "select username from connections;";

    rc = sqlite3_prepare_v2(history_db, sql.c_str(), -1, &statement, NULL);

    if (rc != SQLITE_OK)
    {
        std::cout << "Retrieve error: " << sqlite3_errmsg(history_db) << '\n';

        response = "re.";
        encrypt(response, key);
        send_response(socket_, response);

        sqlite3_close(history_db);
        sqlite3_finalize(statement);

        return;
    }

    sqlite3_bind_int(statement, 1, 1);

    while ((rc = sqlite3_step(statement)) == SQLITE_ROW)
    {
        line.clear();
        line = "retrieve_connections-" + std::string((const char *) sqlite3_column_text(statement, 0));

        encrypt(line, key);
        history.push_back(line);
    }

    line.clear();
    line = "retrieve_connections-<eof>";
    encrypt(line, key);
    history.push_back(line);

    if (rc != SQLITE_DONE)
    {
        std::cout << "Retrieve error: " << sqlite3_errmsg(history_db) << '\n';

        response = "re.";
        encrypt(response, key);
        send_response(socket_, response);

        sqlite3_close(history_db);
        sqlite3_finalize(statement);

        return;
    }

    sqlite3_finalize(statement);
    sqlite3_close(history_db);

    for (std::string& line: history)
    {
        send_response(socket_, line);

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void add_connection(tcp::socket& socket_, std::string& username, std::string& connection_username, RSA* sender_key, bool is_online, tcp::socket& recipient_socket_, RSA* recipient_key)
{
    std::string response = "";
    std::string found_username = "";

    sqlite3* accounts_db;
    int rc = sqlite3_open("../db/accounts.db", &accounts_db);

    if (rc)
    {
        std::cout << "Connection error: " << sqlite3_errmsg(accounts_db) << '\n';

        response = "ce.";
        encrypt(response, sender_key);
        send_response(socket_, response);

        sqlite3_close(accounts_db);

        return;
    }

    sqlite3_stmt* statement;
    std::string sql = "select username from users where username=\"" +
                      connection_username + "\";";

    rc = sqlite3_prepare_v2(accounts_db, sql.c_str(), -1, &statement, NULL);

    if (rc != SQLITE_OK)
    {
        std::cout << "Connection error: " << sqlite3_errmsg(accounts_db) << '\n';

        response = "ce.";
        encrypt(response, sender_key);
        send_response(socket_, response);

        sqlite3_close(accounts_db);
        sqlite3_finalize(statement);

        return;
    }

    sqlite3_bind_int(statement, 1, 1);

    rc = sqlite3_step(statement);

    if (rc == SQLITE_ROW)
    {
        found_username = (const char*) sqlite3_column_text(statement, 0);
    }
    else
    {
        std::cout << "No user with such username.\n";

        response = "nuwsu.";
        encrypt(response, sender_key);
        send_response(socket_, response);

        sqlite3_close(accounts_db);
        sqlite3_finalize(statement);

        return;
    }

    sqlite3_finalize(statement);
    sqlite3_close(accounts_db);

    // insert connection_username
    sqlite3* connections_db;
    rc = sqlite3_open(("../db/" + username + "/connections.db").c_str(), &connections_db);

    if (rc)
    {
        std::cout << "Connection error: " << sqlite3_errmsg(connections_db) << '\n';

        response = "ce.";
        encrypt(response, sender_key);
        send_response(socket_, response);

        sqlite3_close(connections_db);

        return;
    }

    char* error_message = 0;
    sql = "insert into connections values(\"" + connection_username + "\");";

    sqlite3_exec(connections_db, sql.c_str(), callback, 0, &error_message);

    if (rc != SQLITE_OK)
    {
        std::cout << "Connection error: " << error_message << '\n';

        response = "ce.";
        encrypt(response, sender_key);
        send_response(socket_, response);

        sqlite3_free(error_message);
        sqlite3_close(connections_db);

        return;
    }

    sqlite3_close(connections_db);

    // insert username
    rc = sqlite3_open(("../db/" + connection_username + "/connections.db").c_str(), &connections_db);

    if (rc)
    {
        std::cout << "Connection error: " << sqlite3_errmsg(connections_db) << '\n';

        if (is_online)
        {
            response = "ce.";
            encrypt(response, recipient_key);
            send_response(recipient_socket_, response);
        }

        sqlite3_close(connections_db);

        return;
    }

    error_message = 0;
    sql = "insert into connections values(\"" + username + "\");";

    sqlite3_exec(connections_db, sql.c_str(), callback, 0, &error_message);

    if (rc != SQLITE_OK)
    {
        std::cout << "Connection error: " << error_message << '\n';

        if (is_online)
        {
            response = "ce.";
            encrypt(response, recipient_key);
            send_response(recipient_socket_, response);
        }

        sqlite3_free(error_message);
        sqlite3_close(connections_db);

        return;
    }

    sqlite3_close(connections_db);

    response = "connect-" + connection_username;
    encrypt(response, sender_key);
    send_response(socket_, response);

    if (is_online)
    {
        response = "connect-" + username;
        encrypt(response, recipient_key);
        send_response(recipient_socket_, response);
    }
}

void send_response(tcp::socket& socket, std::string& response)
{
    std::string response_size = std::to_string(response.size()) + delimeter;
    std::shared_ptr<std::string> response_ptr = std::make_shared<std::string>(response);

    asio::async_write(socket, asio::buffer(response_size.data(), response_size.size()),
        [&socket, response_ptr](std::error_code ec, std::size_t bytes){
            if (ec)
            {
                std::cout << "Error sending response size: " << ec.message() << '\n';
            }
        });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    asio::async_write(socket, asio::buffer(response_ptr->data(), response_ptr->size()),
        [](std::error_code ec, std::size_t bytes){
            if (ec)
            {
                std::cout << "Error sending response: " << ec.message() << '\n';
            }
        });
}

static int callback(void* data, int argc, char** argv, char** azColName)
{
    for (int i = 0; i<argc; i++)
        std::cout << azColName[i] << " = " << (argv[i] ? argv[i] : "NULL") << '\n';

    return 0;
}
