#include "crow.h"
#include "crow/middlewares/cors.h"

#include <pqxx/pqxx>
#include <jwt-cpp/jwt.h>
#include <bcrypt/BCrypt.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <iostream>
#include <stdexcept>
#include <cstdlib>
#include <sstream>
#include <chrono>

using json = nlohmann::json;

// Helpers

static std::string env(const char* key, const char* def = "") {
    const char* v = std::getenv(key);
    return v ? v : def;
}

static const std::string DB_CONN  = env("DATABASE_URL", "host=localhost dbname=tickets user=postgres password=postgres");
static const std::string JWT_SECRET = env("JWT_SECRET", "super-secret-key-change-in-production");

// Моделирование общего пула подключений: создание нового соединения по запросу (простой подход)
pqxx::connection make_conn() { return pqxx::connection(DB_CONN); }

// JWT helpers

std::string make_token(int user_id, const std::string& role) {
    auto now = std::chrono::system_clock::now();
    return jwt::create()
        .set_type("JWT")
        .set_issuer("ticket-system")
        .set_subject(std::to_string(user_id))
        .set_payload_claim("role", jwt::claim(role))
        .set_issued_at(now)
        .set_expires_at(now + std::chrono::hours(24))
        .sign(jwt::algorithm::hs256{JWT_SECRET});
}

struct TokenInfo { int user_id; std::string role; bool valid; };

TokenInfo verify_token(const std::string& token) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{JWT_SECRET})
            .with_issuer("ticket-system");
        verifier.verify(decoded);
        int uid = std::stoi(decoded.get_subject());
        std::string role = decoded.get_payload_claim("role").as_string();
        return {uid, role, true};
    } catch (...) {
        return {0, "", false};
    }
}

TokenInfo auth_from_request(const crow::request& req) {
    std::string auth = req.get_header_value("Authorization");
    if (auth.substr(0, 7) == "Bearer ")
        return verify_token(auth.substr(7));
    return {0, "", false};
}

// Response helpers

crow::response ok(const json& body) {
    auto r = crow::response(200, body.dump());
    r.add_header("Content-Type", "application/json");
    return r;
}
crow::response created(const json& body) {
    auto r = crow::response(201, body.dump());
    r.add_header("Content-Type", "application/json");
    return r;
}
crow::response err(int code, const std::string& msg) {
    json j = {{"error", msg}};
    auto r = crow::response(code, j.dump());
    r.add_header("Content-Type", "application/json");
    return r;
}

// Main

int main() {
    crow::App<crow::CORSHandler> app;

    app.get_middleware<crow::CORSHandler>()
        .global()
        .headers("Authorization", "Content-Type")
        .methods("GET"_method, "POST"_method, "PUT"_method, "DELETE"_method, "OPTIONS"_method)
        .origin("*");

    // POST /api/auth/login
    CROW_ROUTE(app, "/api/auth/login").methods("POST"_method)
    ([](const crow::request& req) -> crow::response {
        try {
            auto body = json::parse(req.body);
            std::string username = body.value("username", "");
            std::string password = body.value("password", "");
            if (username.empty() || password.empty())
                return err(400, "Необходимо указать логин и пароль");

            auto conn = make_conn();
            pqxx::work tx(conn);
            auto res = tx.exec_params(
                "SELECT u.id, u.password_hash, u.full_name, r.name as role "
                "FROM users u JOIN roles r ON u.role_id = r.id "
                "WHERE u.username = $1 AND u.is_active = TRUE",
                username);
            if (res.empty()) return err(401, "Неверный логин или пароль");

            std::string hash = res[0]["password_hash"].c_str();
            if (!BCrypt::validatePassword(password, hash))
                return err(401, "Неверный логин или пароль");

            int uid = res[0]["id"].as<int>();
            std::string role = res[0]["role"].c_str();
            std::string full_name = res[0]["full_name"].c_str();
            tx.commit();

            std::string token = make_token(uid, role);
            json resp = {
                {"token", token},
                {"user", {{"id", uid}, {"username", username}, {"full_name", full_name}, {"role", role}}}
            };
            return ok(resp);
        } catch (const std::exception& e) {
            return err(500, e.what());
        }
    });

    // POST /api/auth/register
    CROW_ROUTE(app, "/api/auth/register").methods("POST"_method)
    ([](const crow::request& req) -> crow::response {
        try {
            auto body = json::parse(req.body);
            std::string username  = body.value("username", "");
            std::string email     = body.value("email", "");
            std::string password  = body.value("password", "");
            std::string full_name = body.value("full_name", "");
            if (username.empty() || email.empty() || password.empty())
                return err(400, "Заполните все обязательные поля");

            std::string hash = BCrypt::generateHash(password);
            auto conn = make_conn();
            pqxx::work tx(conn);
            try {
                auto res = tx.exec_params(
                    "INSERT INTO users (username, email, password_hash, full_name) "
                    "VALUES ($1,$2,$3,$4) RETURNING id",
                    username, email, hash, full_name);
                int uid = res[0]["id"].as<int>();
                tx.commit();
                std::string token = make_token(uid, "user");
                json resp = {
                    {"token", token},
                    {"user", {{"id", uid}, {"username", username}, {"full_name", full_name}, {"role", "user"}}}
                };
                return created(resp);
            } catch (const pqxx::unique_violation&) {
                return err(409, "Пользователь с таким логином или email уже существует");
            }
        } catch (const std::exception& e) {
            return err(500, e.what());
        }
    });

    // GET /api/auth/me
    CROW_ROUTE(app, "/api/auth/me").methods("GET"_method)
    ([](const crow::request& req) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            auto conn = make_conn();
            pqxx::work tx(conn);
            auto res = tx.exec_params(
                "SELECT u.id, u.username, u.email, u.full_name, r.name as role "
                "FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = $1",
                ti.user_id);
            if (res.empty()) return err(404, "Пользователь не найден");
            json j = {
                {"id", res[0]["id"].as<int>()},
                {"username", res[0]["username"].c_str()},
                {"email", res[0]["email"].c_str()},
                {"full_name", res[0]["full_name"].c_str()},
                {"role", res[0]["role"].c_str()}
            };
            return ok(j);
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // GET /api/tickets
    CROW_ROUTE(app, "/api/tickets").methods("GET"_method)
    ([](const crow::request& req) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            std::string status_filter   = req.url_params.get("status")   ? req.url_params.get("status")   : "";
            std::string category_filter = req.url_params.get("category") ? req.url_params.get("category") : "";
            std::string search          = req.url_params.get("search")   ? req.url_params.get("search")   : "";
            std::string priority_filter = req.url_params.get("priority") ? req.url_params.get("priority") : "";

            std::string sql =
                "SELECT t.id, t.title, t.description, t.created_at, t.updated_at, t.due_date, "
                "  s.name as status, s.color as status_color, "
                "  p.name as priority, p.color as priority_color, p.level as priority_level, "
                "  c.name as category, c.color as category_color, "
                "  u1.full_name as creator_name, u1.username as creator_username, t.creator_id, "
                "  u2.full_name as assignee_name, u2.username as assignee_username, t.assignee_id "
                "FROM tickets t "
                "JOIN statuses s ON t.status_id = s.id "
                "JOIN priorities p ON t.priority_id = p.id "
                "LEFT JOIN categories c ON t.category_id = c.id "
                "JOIN users u1 ON t.creator_id = u1.id "
                "LEFT JOIN users u2 ON t.assignee_id = u2.id "
                "WHERE 1=1 ";

            // Фильтрация на основе ролей: обычные пользователи видят только свои собственные заявки
            std::vector<std::string> cond;
            std::vector<std::string> params;
            int pi = 1;

            if (ti.role == "user") {
                cond.push_back("t.creator_id = $" + std::to_string(pi++));
                params.push_back(std::to_string(ti.user_id));
            }
            if (!status_filter.empty()) {
                cond.push_back("s.name = $" + std::to_string(pi++));
                params.push_back(status_filter);
            }
            if (!category_filter.empty()) {
                cond.push_back("c.name = $" + std::to_string(pi++));
                params.push_back(category_filter);
            }
            if (!priority_filter.empty()) {
                cond.push_back("p.name = $" + std::to_string(pi++));
                params.push_back(priority_filter);
            }
            if (!search.empty()) {
                cond.push_back("(t.title ILIKE $" + std::to_string(pi) +
                               " OR t.description ILIKE $" + std::to_string(pi) + ")");
                params.push_back("%" + search + "%");
                pi++;
            }
            for (const auto& c : cond) sql += " AND " + c;
            sql += " ORDER BY p.level DESC, t.created_at DESC";

            auto conn = make_conn();
            pqxx::work tx(conn);
            pqxx::result res;

            // Выполнение с правильным количеством параметров
            switch (params.size()) {
                case 0: res = tx.exec(sql); break;
                case 1: res = tx.exec_params(sql, params[0]); break;
                case 2: res = tx.exec_params(sql, params[0], params[1]); break;
                case 3: res = tx.exec_params(sql, params[0], params[1], params[2]); break;
                case 4: res = tx.exec_params(sql, params[0], params[1], params[2], params[3]); break;
                default: res = tx.exec(sql);
            }

            json arr = json::array();
            for (const auto& row : res) {
                json t;
                t["id"]               = row["id"].as<int>();
                t["title"]            = row["title"].c_str();
                t["description"]      = row["description"].is_null() ? "" : row["description"].c_str();
                t["created_at"]       = row["created_at"].c_str();
                t["updated_at"]       = row["updated_at"].c_str();
                t["due_date"]         = row["due_date"].is_null() ? nullptr : json(row["due_date"].c_str());
                t["status"]           = row["status"].c_str();
                t["status_color"]     = row["status_color"].c_str();
                t["priority"]         = row["priority"].c_str();
                t["priority_color"]   = row["priority_color"].c_str();
                t["priority_level"]   = row["priority_level"].as<int>();
                t["category"]         = row["category"].is_null() ? "" : row["category"].c_str();
                t["category_color"]   = row["category_color"].is_null() ? "#6c757d" : row["category_color"].c_str();
                t["creator_name"]     = row["creator_name"].c_str();
                t["creator_username"] = row["creator_username"].c_str();
                t["creator_id"]       = row["creator_id"].as<int>();
                t["assignee_name"]    = row["assignee_name"].is_null() ? "" : row["assignee_name"].c_str();
                t["assignee_id"]      = row["assignee_id"].is_null() ? 0 : row["assignee_id"].as<int>();
                arr.push_back(t);
            }
            return ok(arr);
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // GET /api/tickets/:id
    CROW_ROUTE(app, "/api/tickets/<int>").methods("GET"_method)
    ([](const crow::request& req, int id) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            auto conn = make_conn();
            pqxx::work tx(conn);
            auto res = tx.exec_params(
                "SELECT t.id, t.title, t.description, t.created_at, t.updated_at, t.due_date, t.closed_at, "
                "  s.id as status_id, s.name as status, s.color as status_color, "
                "  p.id as priority_id, p.name as priority, p.color as priority_color, p.level as priority_level, "
                "  c.id as category_id, c.name as category, c.color as category_color, "
                "  u1.id as creator_id, u1.full_name as creator_name, u1.username as creator_username, "
                "  u2.id as assignee_id, u2.full_name as assignee_name, u2.username as assignee_username "
                "FROM tickets t "
                "JOIN statuses s ON t.status_id = s.id "
                "JOIN priorities p ON t.priority_id = p.id "
                "LEFT JOIN categories c ON t.category_id = c.id "
                "JOIN users u1 ON t.creator_id = u1.id "
                "LEFT JOIN users u2 ON t.assignee_id = u2.id "
                "WHERE t.id = $1", id);
            if (res.empty()) return err(404, "Заявка не найдена");

            const auto& row = res[0];
            // Проверка доступа: обычные пользователи могут просматривать только свои собственные билеты
            if (ti.role == "user" && row["creator_id"].as<int>() != ti.user_id)
                return err(403, "Нет доступа");

            json t;
            t["id"]               = row["id"].as<int>();
            t["title"]            = row["title"].c_str();
            t["description"]      = row["description"].is_null() ? "" : row["description"].c_str();
            t["created_at"]       = row["created_at"].c_str();
            t["updated_at"]       = row["updated_at"].c_str();
            t["due_date"]         = row["due_date"].is_null() ? nullptr : json(row["due_date"].c_str());
            t["closed_at"]        = row["closed_at"].is_null() ? nullptr : json(row["closed_at"].c_str());
            t["status_id"]        = row["status_id"].as<int>();
            t["status"]           = row["status"].c_str();
            t["status_color"]     = row["status_color"].c_str();
            t["priority_id"]      = row["priority_id"].as<int>();
            t["priority"]         = row["priority"].c_str();
            t["priority_color"]   = row["priority_color"].c_str();
            t["priority_level"]   = row["priority_level"].as<int>();
            t["category_id"]      = row["category_id"].is_null() ? 0 : row["category_id"].as<int>();
            t["category"]         = row["category"].is_null() ? "" : row["category"].c_str();
            t["category_color"]   = row["category_color"].is_null() ? "#6c757d" : row["category_color"].c_str();
            t["creator_id"]       = row["creator_id"].as<int>();
            t["creator_name"]     = row["creator_name"].c_str();
            t["creator_username"] = row["creator_username"].c_str();
            t["assignee_id"]      = row["assignee_id"].is_null() ? 0 : row["assignee_id"].as<int>();
            t["assignee_name"]    = row["assignee_name"].is_null() ? "" : row["assignee_name"].c_str();

            // Комментарии
            auto cres = tx.exec_params(
                "SELECT c.id, c.content, c.created_at, u.full_name as author_name, u.username "
                "FROM comments c JOIN users u ON c.author_id = u.id "
                "WHERE c.ticket_id = $1 ORDER BY c.created_at", id);
            json comments = json::array();
            for (const auto& cr : cres) {
                comments.push_back({
                    {"id", cr["id"].as<int>()},
                    {"content", cr["content"].c_str()},
                    {"created_at", cr["created_at"].c_str()},
                    {"author_name", cr["author_name"].c_str()},
                    {"username", cr["username"].c_str()}
                });
            }
            t["comments"] = comments;

            // История
            auto hres = tx.exec_params(
                "SELECT h.field, h.old_value, h.new_value, h.changed_at, u.full_name "
                "FROM ticket_history h JOIN users u ON h.user_id = u.id "
                "WHERE h.ticket_id = $1 ORDER BY h.changed_at DESC LIMIT 20", id);
            json history = json::array();
            for (const auto& hr : hres) {
                history.push_back({
                    {"field", hr["field"].c_str()},
                    {"old_value", hr["old_value"].is_null() ? "" : hr["old_value"].c_str()},
                    {"new_value", hr["new_value"].is_null() ? "" : hr["new_value"].c_str()},
                    {"changed_at", hr["changed_at"].c_str()},
                    {"full_name", hr["full_name"].c_str()}
                });
            }
            t["history"] = history;
            tx.commit();
            return ok(t);
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // POST /api/tickets
    CROW_ROUTE(app, "/api/tickets").methods("POST"_method)
    ([](const crow::request& req) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            auto body = json::parse(req.body);
            std::string title = body.value("title", "");
            if (title.empty()) return err(400, "Название заявки обязательно");
            std::string description = body.value("description", "");
            int status_id   = body.value("status_id", 1);
            int priority_id = body.value("priority_id", 2);
            int category_id = body.value("category_id", 0);
            std::string due_date = body.value("due_date", "");

            auto conn = make_conn();
            pqxx::work tx(conn);
            pqxx::result res;
            if (category_id > 0 && !due_date.empty()) {
                res = tx.exec_params(
                    "INSERT INTO tickets (title, description, status_id, priority_id, category_id, creator_id, due_date) "
                    "VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
                    title, description, status_id, priority_id, category_id, ti.user_id, due_date);
            } else if (category_id > 0) {
                res = tx.exec_params(
                    "INSERT INTO tickets (title, description, status_id, priority_id, category_id, creator_id) "
                    "VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
                    title, description, status_id, priority_id, category_id, ti.user_id);
            } else {
                res = tx.exec_params(
                    "INSERT INTO tickets (title, description, status_id, priority_id, creator_id) "
                    "VALUES ($1,$2,$3,$4,$5) RETURNING id",
                    title, description, status_id, priority_id, ti.user_id);
            }
            int new_id = res[0]["id"].as<int>();
            tx.commit();
            return created({{"id", new_id}, {"message", "Заявка создана"}});
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // PUT /api/tickets/:id
    CROW_ROUTE(app, "/api/tickets/<int>").methods("PUT"_method)
    ([](const crow::request& req, int id) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            auto body = json::parse(req.body);
            auto conn = make_conn();
            pqxx::work tx(conn);

            // Получить текущий билет
            auto cur = tx.exec_params("SELECT * FROM tickets WHERE id = $1", id);
            if (cur.empty()) return err(404, "Заявка не найдена");

            // Редактировать может только создатель или admin/manager
            if (ti.role == "user" && cur[0]["creator_id"].as<int>() != ti.user_id)
                return err(403, "Нет доступа");

            // История записей для измененных полей
            auto log_change = [&](const std::string& field, const std::string& old_val, const std::string& new_val) {
                if (old_val != new_val) {
                    tx.exec_params(
                        "INSERT INTO ticket_history (ticket_id, user_id, field, old_value, new_value) "
                        "VALUES ($1,$2,$3,$4,$5)",
                        id, ti.user_id, field, old_val, new_val);
                }
            };

            std::string title       = body.value("title", cur[0]["title"].c_str());
            std::string description = body.value("description", cur[0]["description"].is_null() ? "" : cur[0]["description"].c_str());
            int status_id   = body.value("status_id",   cur[0]["status_id"].as<int>());
            int priority_id = body.value("priority_id", cur[0]["priority_id"].as<int>());

            log_change("title",       cur[0]["title"].c_str(), title);
            log_change("description", cur[0]["description"].is_null() ? "" : cur[0]["description"].c_str(), description);
            log_change("status_id",   cur[0]["status_id"].c_str(),   std::to_string(status_id));
            log_change("priority_id", cur[0]["priority_id"].c_str(), std::to_string(priority_id));

            // Обращение к правоприемнику (только к admin/manager)
            int assignee_id = cur[0]["assignee_id"].is_null() ? 0 : cur[0]["assignee_id"].as<int>();
            if (body.contains("assignee_id") && ti.role != "user") {
                int new_assignee = body["assignee_id"].get<int>();
                log_change("assignee_id", std::to_string(assignee_id), std::to_string(new_assignee));
                assignee_id = new_assignee;
            }

            // Установка closed_at если статус равен 4 (Выполнена) или 5 (Отклонена)
            std::string closed_sql = status_id >= 4
                ? ", closed_at = NOW()"
                : ", closed_at = NULL";

            if (assignee_id > 0) {
                tx.exec_params(
                    "UPDATE tickets SET title=$1, description=$2, status_id=$3, priority_id=$4, assignee_id=$5" + closed_sql + " WHERE id=$6",
                    title, description, status_id, priority_id, assignee_id, id);
            } else {
                tx.exec_params(
                    "UPDATE tickets SET title=$1, description=$2, status_id=$3, priority_id=$4" + closed_sql + " WHERE id=$5",
                    title, description, status_id, priority_id, id);
            }
            tx.commit();
            return ok({{"message", "Заявка обновлена"}});
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // DELETE /api/tickets/:id
    CROW_ROUTE(app, "/api/tickets/<int>").methods("DELETE"_method)
    ([](const crow::request& req, int id) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        if (ti.role != "admin") return err(403, "Только администратор может удалять заявки");
        try {
            auto conn = make_conn();
            pqxx::work tx(conn);
            tx.exec_params("DELETE FROM tickets WHERE id = $1", id);
            tx.commit();
            return ok({{"message", "Заявка удалена"}});
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // POST /api/tickets/:id/comments
    CROW_ROUTE(app, "/api/tickets/<int>/comments").methods("POST"_method)
    ([](const crow::request& req, int ticket_id) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            auto body = json::parse(req.body);
            std::string content = body.value("content", "");
            if (content.empty()) return err(400, "Текст комментария обязателен");

            auto conn = make_conn();
            pqxx::work tx(conn);
            auto res = tx.exec_params(
                "INSERT INTO comments (ticket_id, author_id, content) VALUES ($1,$2,$3) RETURNING id",
                ticket_id, ti.user_id, content);
            tx.commit();
            return created({{"id", res[0]["id"].as<int>()}, {"message", "Комментарий добавлен"}});
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // GET /api/categories
    CROW_ROUTE(app, "/api/categories").methods("GET"_method)
    ([](const crow::request& req) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            auto conn = make_conn();
            pqxx::work tx(conn);
            auto res = tx.exec("SELECT id, name, description, color FROM categories ORDER BY name");
            json arr = json::array();
            for (const auto& row : res) {
                arr.push_back({
                    {"id", row["id"].as<int>()},
                    {"name", row["name"].c_str()},
                    {"description", row["description"].is_null() ? "" : row["description"].c_str()},
                    {"color", row["color"].c_str()}
                });
            }
            return ok(arr);
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // GET /api/statuses
    CROW_ROUTE(app, "/api/statuses").methods("GET"_method)
    ([](const crow::request& req) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            auto conn = make_conn();
            pqxx::work tx(conn);
            auto res = tx.exec("SELECT id, name, color FROM statuses ORDER BY id");
            json arr = json::array();
            for (const auto& row : res) {
                arr.push_back({
                    {"id", row["id"].as<int>()},
                    {"name", row["name"].c_str()},
                    {"color", row["color"].c_str()}
                });
            }
            return ok(arr);
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // GET /api/priorities
    CROW_ROUTE(app, "/api/priorities").methods("GET"_method)
    ([](const crow::request& req) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            auto conn = make_conn();
            pqxx::work tx(conn);
            auto res = tx.exec("SELECT id, name, level, color FROM priorities ORDER BY level");
            json arr = json::array();
            for (const auto& row : res) {
                arr.push_back({
                    {"id", row["id"].as<int>()},
                    {"name", row["name"].c_str()},
                    {"level", row["level"].as<int>()},
                    {"color", row["color"].c_str()}
                });
            }
            return ok(arr);
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // GET /api/users
    CROW_ROUTE(app, "/api/users").methods("GET"_method)
    ([](const crow::request& req) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        if (ti.role == "user") return err(403, "Нет доступа");
        try {
            auto conn = make_conn();
            pqxx::work tx(conn);
            auto res = tx.exec(
                "SELECT u.id, u.username, u.full_name, u.email, r.name as role "
                "FROM users u JOIN roles r ON u.role_id = r.id "
                "WHERE u.is_active = TRUE ORDER BY u.full_name");
            json arr = json::array();
            for (const auto& row : res) {
                arr.push_back({
                    {"id", row["id"].as<int>()},
                    {"username", row["username"].c_str()},
                    {"full_name", row["full_name"].is_null() ? "" : row["full_name"].c_str()},
                    {"email", row["email"].c_str()},
                    {"role", row["role"].c_str()}
                });
            }
            return ok(arr);
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // GET /api/stats
    CROW_ROUTE(app, "/api/stats").methods("GET"_method)
    ([](const crow::request& req) -> crow::response {
        auto ti = auth_from_request(req);
        if (!ti.valid) return err(401, "Не авторизован");
        try {
            auto conn = make_conn();
            pqxx::work tx(conn);

            std::string where = (ti.role == "user")
                ? "WHERE t.creator_id = " + std::to_string(ti.user_id)
                : "";

            auto total = tx.exec("SELECT COUNT(*) FROM tickets t " + where);
            auto by_status = tx.exec(
                "SELECT s.name, s.color, COUNT(t.id) as cnt "
                "FROM statuses s LEFT JOIN tickets t ON t.status_id = s.id " + where +
                " GROUP BY s.id, s.name, s.color ORDER BY s.id");
            auto by_priority = tx.exec(
                "SELECT p.name, p.color, COUNT(t.id) as cnt "
                "FROM priorities p LEFT JOIN tickets t ON t.priority_id = p.id " + where +
                " GROUP BY p.id, p.name, p.color ORDER BY p.level");

            json stats;
            stats["total"] = total[0][0].as<int>();
            stats["by_status"] = json::array();
            for (const auto& r : by_status) {
                stats["by_status"].push_back({
                    {"name", r["name"].c_str()},
                    {"color", r["color"].c_str()},
                    {"count", r["cnt"].as<int>()}
                });
            }
            stats["by_priority"] = json::array();
            for (const auto& r : by_priority) {
                stats["by_priority"].push_back({
                    {"name", r["name"].c_str()},
                    {"color", r["color"].c_str()},
                    {"count", r["cnt"].as<int>()}
                });
            }
            tx.commit();
            return ok(stats);
        } catch (const std::exception& e) { return err(500, e.what()); }
    });

    // Health check
    CROW_ROUTE(app, "/api/health")
    ([]() { return crow::response(200, "{\"status\":\"ok\"}"); });

    int port = std::stoi(env("PORT", "8080"));
    std::cout << "Starting Ticket System backend on port " << port << std::endl;
    app.port(port).multithreaded().run();
    return 0;
}
