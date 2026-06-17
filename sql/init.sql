-- ============================================================
-- Система учёта заявок и задач организации
-- Скрипт инициализации базы данных
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Таблица ролей
CREATE TABLE IF NOT EXISTS roles (
    id   SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL  -- admin, manager, user
);

INSERT INTO roles (name) VALUES ('admin'), ('manager'), ('user')
ON CONFLICT DO NOTHING;

-- Таблица пользователей
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(100) UNIQUE NOT NULL,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role_id       INTEGER NOT NULL REFERENCES roles(id) DEFAULT 3,
    full_name     VARCHAR(255),
    created_at    TIMESTAMP DEFAULT NOW(),
    is_active     BOOLEAN DEFAULT TRUE
);

-- Таблица категорий заявок
CREATE TABLE IF NOT EXISTS categories (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    color       VARCHAR(7) DEFAULT '#6c757d'
);

INSERT INTO categories (name, description, color) VALUES
    ('IT-поддержка',    'Проблемы с оборудованием и программным обеспечением', '#007bff'),
    ('Административные','Административные вопросы',                             '#6c757d'),
    ('HR',              'Кадровые вопросы',                                    '#28a745'),
    ('Закупки',         'Заявки на приобретение товаров и услуг',              '#ffc107'),
    ('Безопасность',    'Вопросы информационной безопасности',                 '#dc3545')
ON CONFLICT DO NOTHING;

-- Таблица статусов
CREATE TABLE IF NOT EXISTS statuses (
    id    SERIAL PRIMARY KEY,
    name  VARCHAR(50) UNIQUE NOT NULL,
    color VARCHAR(7) DEFAULT '#6c757d'
);

INSERT INTO statuses (name, color) VALUES
    ('Новая',       '#007bff'),
    ('В работе',    '#ffc107'),
    ('На проверке', '#17a2b8'),
    ('Выполнена',   '#28a745'),
    ('Отклонена',   '#dc3545')
ON CONFLICT DO NOTHING;

-- Таблица приоритетов
CREATE TABLE IF NOT EXISTS priorities (
    id    SERIAL PRIMARY KEY,
    name  VARCHAR(50) UNIQUE NOT NULL,
    level INTEGER NOT NULL,
    color VARCHAR(7) DEFAULT '#6c757d'
);

INSERT INTO priorities (name, level, color) VALUES
    ('Низкий',    1, '#28a745'),
    ('Средний',   2, '#ffc107'),
    ('Высокий',   3, '#fd7e14'),
    ('Критичный', 4, '#dc3545')
ON CONFLICT DO NOTHING;

-- Таблица заявок
CREATE TABLE IF NOT EXISTS tickets (
    id           SERIAL PRIMARY KEY,
    title        VARCHAR(255) NOT NULL,
    description  TEXT,
    status_id    INTEGER NOT NULL REFERENCES statuses(id) DEFAULT 1,
    priority_id  INTEGER NOT NULL REFERENCES priorities(id) DEFAULT 2,
    category_id  INTEGER REFERENCES categories(id),
    creator_id   INTEGER NOT NULL REFERENCES users(id),
    assignee_id  INTEGER REFERENCES users(id),
    created_at   TIMESTAMP DEFAULT NOW(),
    updated_at   TIMESTAMP DEFAULT NOW(),
    due_date     TIMESTAMP,
    closed_at    TIMESTAMP
);

-- Таблица комментариев
CREATE TABLE IF NOT EXISTS comments (
    id         SERIAL PRIMARY KEY,
    ticket_id  INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_id  INTEGER NOT NULL REFERENCES users(id),
    content    TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Таблица истории изменений заявок
CREATE TABLE IF NOT EXISTS ticket_history (
    id         SERIAL PRIMARY KEY,
    ticket_id  INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    field      VARCHAR(100) NOT NULL,
    old_value  TEXT,
    new_value  TEXT,
    changed_at TIMESTAMP DEFAULT NOW()
);

-- Таблица сессий (JWT-токены хранятся на клиенте, здесь — refresh-токены)
CREATE TABLE IF NOT EXISTS sessions (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      VARCHAR(512) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
);

-- Индексы
CREATE INDEX IF NOT EXISTS idx_tickets_status    ON tickets(status_id);
CREATE INDEX IF NOT EXISTS idx_tickets_creator   ON tickets(creator_id);
CREATE INDEX IF NOT EXISTS idx_tickets_assignee  ON tickets(assignee_id);
CREATE INDEX IF NOT EXISTS idx_tickets_category  ON tickets(category_id);
CREATE INDEX IF NOT EXISTS idx_comments_ticket   ON comments(ticket_id);
CREATE INDEX IF NOT EXISTS idx_history_ticket    ON ticket_history(ticket_id);

-- Триггер обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tickets_updated_at ON tickets;
CREATE TRIGGER trg_tickets_updated_at
    BEFORE UPDATE ON tickets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ===================== Тестовые данные =====================

-- Пользователи (пароль: "password123" — bcrypt-хеш)
INSERT INTO users (username, email, password_hash, role_id, full_name) VALUES
    ('admin',   'admin@company.ru',   '$2a$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.', 1, 'Администратор Системы'),
    ('manager', 'manager@company.ru', '$2a$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.', 2, 'Иванов Иван Иванович'),
    ('user1',   'user1@company.ru',   '$2a$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.', 3, 'Петрова Мария Сергеевна'),
    ('user2',   'user2@company.ru',   '$2a$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.', 3, 'Сидоров Алексей Николаевич')
ON CONFLICT DO NOTHING;

-- Тестовые заявки
INSERT INTO tickets (title, description, status_id, priority_id, category_id, creator_id, assignee_id) VALUES
    ('Не работает принтер в офисе 201', 'Принтер HP LaserJet не печатает документы. Светится красная лампочка.',    2, 2, 1, 3, 2),
    ('Запрос на установку программы',   'Необходимо установить MS Office 2021 на рабочий компьютер сотрудника.',      1, 1, 1, 3, NULL),
    ('Сброс пароля учётной записи',     'Пользователь забыл пароль от корпоративного аккаунта.',                      3, 3, 1, 4, 2),
    ('Закупка канцелярских товаров',    'Требуются ручки, бумага А4 (10 пачек), степлеры — для отдела бухгалтерии.',  1, 1, 4, 3, NULL),
    ('Проблема с доступом к серверу',   'Не могу подключиться к файловому серверу \\SERVER01\share.',                  2, 4, 5, 4, 2)
ON CONFLICT DO NOTHING;

-- Тестовые комментарии
INSERT INTO comments (ticket_id, author_id, content) VALUES
    (1, 2, 'Принял заявку в работу. Приду в 14:00 проверить устройство.'),
    (1, 3, 'Спасибо! Буду на месте.'),
    (3, 2, 'Отправил инструкцию на почту. Проверьте папку "Спам".'),
    (5, 2, 'Проверяю настройки брандмауэра.')
ON CONFLICT DO NOTHING;
