// ============================================================
// Автотесты — Система учёта заявок
// Файл: tests/run_tests.cpp
//
// Сборка (внутри контейнера или на машине с libcurl):
//   g++ run_tests.cpp -o run_tests -lcurl -std=c++17
//
// Запуск:
//   ./run_tests
//   ./run_tests http://localhost:8080  (другой адрес)
// ============================================================

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <curl/curl.h>
#include <sstream>

// ─── Цвета для вывода ─────────────────────────────────────────────────────────
#define GREEN  "\033[32m"
#define RED    "\033[31m"
#define YELLOW "\033[33m"
#define CYAN   "\033[36m"
#define BOLD   "\033[1m"
#define RESET  "\033[0m"

// ─── Базовый URL (можно переопределить аргументом командной строки) ────────────
std::string BASE_URL = "http://localhost:8080";

// ─── Глобальный токен (заполняется после логина) ──────────────────────────────
std::string admin_token   = "";
std::string manager_token = "";
std::string user1_token   = "";
std::string user2_token   = "";
int created_ticket_id     = 0;

// ─── Структура результата теста ───────────────────────────────────────────────
struct TestResult {
    std::string name;
    bool passed;
    std::string detail;
};

std::vector<TestResult> results;
int pass_count = 0;
int fail_count = 0;

// ─── HTTP-ответ ───────────────────────────────────────────────────────────────
struct Response {
    int    status;
    std::string body;
};

// ─── Callback для libcurl: собирает тело ответа ───────────────────────────────
static size_t write_cb(char* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append(ptr, size * nmemb);
    return size * nmemb;
}

// ─── Универсальная HTTP-функция ───────────────────────────────────────────────
Response http(const std::string& method,
              const std::string& path,
              const std::string& body = "",
              const std::string& token = "") {
    CURL* curl = curl_easy_init();
    Response resp{0, ""};
    if (!curl) return resp;

    std::string url = BASE_URL + path;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    // Заголовки
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!token.empty()) {
        std::string auth = "Authorization: Bearer " + token;
        headers = curl_slist_append(headers, auth.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Метод
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    } else if (method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    } else if (method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    }

    curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    resp.status = (int)code;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}

// ─── Простой поиск значения в JSON-строке ────────────────────────────────────
// Ищет "key":"value" или "key":value
std::string json_get(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos += search.size();
    while (pos < json.size() && json[pos] == ' ') pos++;
    if (json[pos] == '"') {
        pos++;
        size_t end = json.find('"', pos);
        return json.substr(pos, end - pos);
    } else {
        size_t end = json.find_first_of(",}", pos);
        return json.substr(pos, end - pos);
    }
}

bool json_has(const std::string& json, const std::string& key) {
    return json.find("\"" + key + "\"") != std::string::npos;
}

// ─── Регистрация результата теста ─────────────────────────────────────────────
void record(const std::string& id, const std::string& name,
            bool passed, const std::string& detail = "") {
    results.push_back({id + " " + name, passed, detail});
    if (passed) {
        pass_count++;
        std::cout << GREEN << "  [PASS] " << RESET << id << " — " << name << "\n";
    } else {
        fail_count++;
        std::cout << RED << "  [FAIL] " << RESET << id << " — " << name;
        if (!detail.empty()) std::cout << "\n         " << YELLOW << detail << RESET;
        std::cout << "\n";
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ТЕСТЫ
// ══════════════════════════════════════════════════════════════════════════════

// ─── Блок 1: Авторизация ──────────────────────────────────────────────────────
void test_auth() {
    std::cout << BOLD << CYAN << "\n── Авторизация и регистрация ──\n" << RESET;

    // TC-01: Успешный вход admin
    {
        auto r = http("POST", "/api/auth/login",
                      R"({"username":"admin","password":"password123"})");
        bool ok = r.status == 200 && json_has(r.body, "token");
        if (ok) admin_token = json_get(r.body, "token");
        record("TC-01", "Успешный вход (admin)", ok,
               ok ? "" : "status=" + std::to_string(r.status) + " body=" + r.body);
    }

    // TC-02: Успешный вход manager
    {
        auto r = http("POST", "/api/auth/login",
                      R"({"username":"manager","password":"password123"})");
        bool ok = r.status == 200 && json_has(r.body, "token");
        if (ok) manager_token = json_get(r.body, "token");
        record("TC-02", "Успешный вход (manager)", ok,
               ok ? "" : "status=" + std::to_string(r.status));
    }

    // TC-03: Успешный вход user1
    {
        auto r = http("POST", "/api/auth/login",
                      R"({"username":"user1","password":"password123"})");
        bool ok = r.status == 200 && json_has(r.body, "token");
        if (ok) user1_token = json_get(r.body, "token");
        record("TC-03", "Успешный вход (user1)", ok,
               ok ? "" : "status=" + std::to_string(r.status));
    }

    // TC-04: Неверный пароль
    {
        auto r = http("POST", "/api/auth/login",
                      R"({"username":"admin","password":"wrongpassword"})");
        record("TC-04", "Неверный пароль → 401", r.status == 401,
               "status=" + std::to_string(r.status));
    }

    // TC-05: Несуществующий пользователь
    {
        auto r = http("POST", "/api/auth/login",
                      R"({"username":"ghost_user_xyz","password":"pass"})");
        record("TC-05", "Несуществующий пользователь → 401", r.status == 401,
               "status=" + std::to_string(r.status));
    }

    // TC-06: Пустые поля
    {
        auto r = http("POST", "/api/auth/login", R"({})");
        record("TC-06", "Пустые поля → 400", r.status == 400,
               "status=" + std::to_string(r.status));
    }

    // TC-07: Регистрация нового пользователя
    {
        std::string unique = "testuser_" + std::to_string(time(nullptr));
        std::string body = R"({"username":")" + unique +
                           R"(","email":")" + unique +
                           R"(@test.com","password":"testpass123","full_name":"Test User"})";
        auto r = http("POST", "/api/auth/register", body);
        bool ok = r.status == 201 && json_has(r.body, "token");
        record("TC-07", "Регистрация нового пользователя → 201", ok,
               ok ? "" : "status=" + std::to_string(r.status) + " " + r.body);
    }

    // TC-08: Дублирующийся логин
    {
        auto r = http("POST", "/api/auth/register",
                      R"({"username":"admin","email":"x@x.com","password":"pass123"})");
        record("TC-08", "Дублирующийся логин → 409", r.status == 409,
               "status=" + std::to_string(r.status));
    }

    // TC-09: GET /api/auth/me с токеном
    {
        auto r = http("GET", "/api/auth/me", "", admin_token);
        bool ok = r.status == 200 && json_get(r.body, "username") == "admin";
        record("TC-09", "GET /api/auth/me → данные пользователя", ok,
               ok ? "" : "body=" + r.body);
    }

    // TC-10: GET /api/auth/me без токена
    {
        auto r = http("GET", "/api/auth/me");
        record("TC-10", "GET /api/auth/me без токена → 401", r.status == 401,
               "status=" + std::to_string(r.status));
    }
}

// ─── Блок 2: Заявки ───────────────────────────────────────────────────────────
void test_tickets() {
    std::cout << BOLD << CYAN << "\n── Работа с заявками ──\n" << RESET;

    // TC-11: Создание заявки
    {
        auto r = http("POST", "/api/tickets",
                      R"({"title":"Автотест заявка","description":"Создана автотестом","priority_id":2})",
                      admin_token);
        bool ok = r.status == 201 && json_has(r.body, "id");
        if (ok) {
            std::string id_str = json_get(r.body, "id");
            if (!id_str.empty()) created_ticket_id = std::stoi(id_str);
        }
        record("TC-11", "Создание заявки → 201", ok,
               ok ? "id=" + std::to_string(created_ticket_id)
                  : "status=" + std::to_string(r.status) + " " + r.body);
    }

    // TC-12: Создание заявки без названия
    {
        auto r = http("POST", "/api/tickets",
                      R"({"title":"","description":"no title"})",
                      admin_token);
        record("TC-12", "Создание без названия → 400", r.status == 400,
               "status=" + std::to_string(r.status));
    }

    // TC-13: Список заявок (admin — видит все)
    {
        auto r = http("GET", "/api/tickets", "", admin_token);
        bool ok = r.status == 200 && r.body[0] == '[';
        record("TC-13", "Список заявок (admin) → 200 + массив", ok,
               ok ? "" : "status=" + std::to_string(r.status));
    }

    // TC-14: Список заявок (user — только свои)
    {
        auto r = http("GET", "/api/tickets", "", user1_token);
        record("TC-14", "Список заявок (user1) → 200", r.status == 200,
               "status=" + std::to_string(r.status));
    }

    // TC-15: Поиск по названию
    {
        auto r = http("GET", "/api/tickets?search=Автотест", "", admin_token);
        record("TC-15", "Поиск по названию → 200", r.status == 200,
               "status=" + std::to_string(r.status));
    }

    // TC-16: Фильтр по статусу
    {
        auto r = http("GET", "/api/tickets?status=%D0%9D%D0%BE%D0%B2%D0%B0%D1%8F",
                      "", admin_token);
        record("TC-16", "Фильтр по статусу → 200", r.status == 200,
               "status=" + std::to_string(r.status));
    }

    // TC-17: Фильтр по категории
    {
        auto r = http("GET", "/api/tickets?category=IT-%D0%BF%D0%BE%D0%B4%D0%B4%D0%B5%D1%80%D0%B6%D0%BA%D0%B0",
                      "", admin_token);
        record("TC-17", "Фильтр по категории → 200", r.status == 200,
               "status=" + std::to_string(r.status));
    }

    // TC-18: Фильтр по приоритету
    {
        auto r = http("GET", "/api/tickets?priority=%D0%9A%D1%80%D0%B8%D1%82%D0%B8%D1%87%D0%BD%D1%8B%D0%B9",
                      "", admin_token);
        record("TC-18", "Фильтр по приоритету → 200", r.status == 200,
               "status=" + std::to_string(r.status));
    }

    // TC-19: Просмотр одной заявки
    if (created_ticket_id > 0) {
        auto r = http("GET", "/api/tickets/" + std::to_string(created_ticket_id),
                      "", admin_token);
        bool ok = r.status == 200 && json_has(r.body, "comments");
        record("TC-19", "Просмотр заявки → 200 + comments", ok,
               ok ? "" : "status=" + std::to_string(r.status));
    } else {
        record("TC-19", "Просмотр заявки", false, "не создана в TC-11");
    }

    // TC-20: Чужая заявка для user (заявка #1 создана admin)
    {
        auto r = http("GET", "/api/tickets/1", "", user1_token);
        // user1 не создавал заявку #1 — должен получить 403
        record("TC-20", "Чужая заявка для user → 403", r.status == 403,
               "status=" + std::to_string(r.status));
    }

    // TC-21: Изменение статуса (manager)
    if (created_ticket_id > 0) {
        auto r = http("PUT", "/api/tickets/" + std::to_string(created_ticket_id),
                      R"({"status_id":2})", manager_token);
        record("TC-21", "Изменение статуса (manager) → 200", r.status == 200,
               "status=" + std::to_string(r.status));
    } else {
        record("TC-21", "Изменение статуса", false, "заявка не создана");
    }

    // TC-22: Назначение исполнителя (manager)
    if (created_ticket_id > 0) {
        auto r = http("PUT", "/api/tickets/" + std::to_string(created_ticket_id),
                      R"({"assignee_id":2})", manager_token);
        record("TC-22", "Назначение исполнителя (manager) → 200", r.status == 200,
               "status=" + std::to_string(r.status));
    } else {
        record("TC-22", "Назначение исполнителя", false, "заявка не создана");
    }

    // TC-23: user меняет свою заявку — создадим заявку от user1
    {
        auto r_create = http("POST", "/api/tickets",
                             R"({"title":"Заявка user1","priority_id":1})",
                             user1_token);
        int user_ticket_id = 0;
        if (r_create.status == 201) {
            std::string id_str = json_get(r_create.body, "id");
            if (!id_str.empty()) user_ticket_id = std::stoi(id_str);
        }
        if (user_ticket_id > 0) {
            auto r = http("PUT", "/api/tickets/" + std::to_string(user_ticket_id),
                          R"({"priority_id":3})", user1_token);
            record("TC-23", "user меняет свою заявку → 200", r.status == 200,
                   "status=" + std::to_string(r.status));
        } else {
            record("TC-23", "user меняет свою заявку", false, "не удалось создать заявку");
        }
    }

    // TC-24: user меняет чужую заявку → 403
    if (created_ticket_id > 0) {
        auto r = http("PUT", "/api/tickets/" + std::to_string(created_ticket_id),
                      R"({"priority_id":1})", user1_token);
        record("TC-24", "user меняет чужую заявку → 403", r.status == 403,
               "status=" + std::to_string(r.status));
    } else {
        record("TC-24", "user меняет чужую заявку", false, "заявка не создана");
    }

    // TC-25 и TC-26 — удаление (делаем в конце чтобы не мешать другим тестам)
}

// ─── Блок 3: Комментарии, справочники, статистика ────────────────────────────
void test_misc() {
    std::cout << BOLD << CYAN << "\n── Комментарии, справочники, статистика ──\n" << RESET;

    // TC-27: Добавление комментария
    if (created_ticket_id > 0) {
        auto r = http("POST",
                      "/api/tickets/" + std::to_string(created_ticket_id) + "/comments",
                      R"({"content":"Автоматический тестовый комментарий"})",
                      admin_token);
        record("TC-27", "Добавление комментария → 201", r.status == 201,
               "status=" + std::to_string(r.status));
    } else {
        record("TC-27", "Добавление комментария", false, "заявка не создана");
    }

    // TC-28: Пустой комментарий
    if (created_ticket_id > 0) {
        auto r = http("POST",
                      "/api/tickets/" + std::to_string(created_ticket_id) + "/comments",
                      R"({"content":""})",
                      admin_token);
        record("TC-28", "Пустой комментарий → 400", r.status == 400,
               "status=" + std::to_string(r.status));
    } else {
        record("TC-28", "Пустой комментарий", false, "заявка не создана");
    }

    // TC-29: Категории
    {
        auto r = http("GET", "/api/categories", "", admin_token);
        bool ok = r.status == 200 && r.body[0] == '[';
        record("TC-29", "GET /api/categories → 200 + массив", ok,
               "status=" + std::to_string(r.status));
    }

    // TC-30: Статусы
    {
        auto r = http("GET", "/api/statuses", "", admin_token);
        bool ok = r.status == 200 && r.body[0] == '[';
        record("TC-30", "GET /api/statuses → 200 + массив", ok,
               "status=" + std::to_string(r.status));
    }

    // TC-31: Приоритеты
    {
        auto r = http("GET", "/api/priorities", "", admin_token);
        bool ok = r.status == 200 && r.body[0] == '[';
        record("TC-31", "GET /api/priorities → 200 + массив", ok,
               "status=" + std::to_string(r.status));
    }

    // TC-32: Статистика (admin)
    {
        auto r = http("GET", "/api/stats", "", admin_token);
        bool ok = r.status == 200 && json_has(r.body, "total");
        record("TC-32", "GET /api/stats (admin) → 200 + total", ok,
               ok ? "total=" + json_get(r.body, "total") : r.body);
    }

    // TC-33: Список пользователей (manager)
    {
        auto r = http("GET", "/api/users", "", manager_token);
        bool ok = r.status == 200 && r.body[0] == '[';
        record("TC-33", "GET /api/users (manager) → 200", ok,
               "status=" + std::to_string(r.status));
    }

    // TC-34: Список пользователей (user) → 403
    {
        auto r = http("GET", "/api/users", "", user1_token);
        record("TC-34", "GET /api/users (user) → 403", r.status == 403,
               "status=" + std::to_string(r.status));
    }

    // TC-35: Health check
    {
        auto r = http("GET", "/api/health");
        bool ok = r.status == 200 && r.body.find("ok") != std::string::npos;
        record("TC-35", "GET /api/health → 200 ok", ok,
               ok ? "" : "status=" + std::to_string(r.status) + " " + r.body);
    }
}

// ─── Удаление (в конце) ───────────────────────────────────────────────────────
void test_delete() {
    std::cout << BOLD << CYAN << "\n── Удаление заявок ──\n" << RESET;

    // TC-26: user пытается удалить → 403
    if (created_ticket_id > 0) {
        auto r = http("DELETE", "/api/tickets/" + std::to_string(created_ticket_id),
                      "", user1_token);
        record("TC-26", "Удаление заявки (user) → 403", r.status == 403,
               "status=" + std::to_string(r.status));
    } else {
        record("TC-26", "Удаление заявки (user)", false, "заявка не создана");
    }

    // TC-25: admin удаляет заявку
    if (created_ticket_id > 0) {
        auto r = http("DELETE", "/api/tickets/" + std::to_string(created_ticket_id),
                      "", admin_token);
        record("TC-25", "Удаление заявки (admin) → 200", r.status == 200,
               "status=" + std::to_string(r.status));
    } else {
        record("TC-25", "Удаление заявки (admin)", false, "заявка не создана");
    }
}

// ─── Итоговый отчёт ───────────────────────────────────────────────────────────
void print_report() {
    std::cout << BOLD << "\n══════════════════════════════════════════\n";
    std::cout << "  ИТОГ: " << pass_count + fail_count << " тестов\n";
    std::cout << "══════════════════════════════════════════\n" << RESET;
    std::cout << GREEN << "  PASS: " << pass_count << RESET << "\n";
    std::cout << RED   << "  FAIL: " << fail_count << RESET << "\n";

    if (fail_count > 0) {
        std::cout << BOLD << RED << "\nПроваленные тесты:\n" << RESET;
        for (auto& r : results) {
            if (!r.passed) {
                std::cout << RED << "  ✗ " << r.name << RESET;
                if (!r.detail.empty())
                    std::cout << " ← " << YELLOW << r.detail << RESET;
                std::cout << "\n";
            }
        }
    } else {
        std::cout << GREEN << BOLD << "\n  Все тесты пройдены! ✓\n" << RESET;
    }
    std::cout << "\n";
}

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc > 1) BASE_URL = argv[1];

    curl_global_init(CURL_GLOBAL_DEFAULT);

    std::cout << BOLD << CYAN;
    std::cout << "══════════════════════════════════════════\n";
    std::cout << "  Автотесты — Система учёта заявок\n";
    std::cout << "  URL: " << BASE_URL << "\n";
    std::cout << "══════════════════════════════════════════\n";
    std::cout << RESET;

    test_auth();
    test_tickets();
    test_misc();
    test_delete();
    print_report();

    curl_global_cleanup();
    return fail_count > 0 ? 1 : 0;
}
