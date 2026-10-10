const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_SECRET = process.env.SESSION_SECRET;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.sqlite");

if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
    console.error("ERROR: Set SESSION_SECRET to at least 32 characters.");
    process.exit(1);
}

if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
}

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        category TEXT NOT NULL DEFAULT 'Other',
        thumbnail TEXT DEFAULT '',
        video_url TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS favorites (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, video_id)
    );

    CREATE TABLE IF NOT EXISTS history (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        video_id INTEGER NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
        watched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, video_id)
    );
`);

const adminEmail = (process.env.ADMIN_EMAIL || "")
    .trim()
    .toLowerCase();

const adminPassword = process.env.ADMIN_PASSWORD || "";

if (adminEmail && adminPassword.length >= 12) {
    const existingAdmin = db.prepare(
        "SELECT id FROM users WHERE email = ?"
    ).get(adminEmail);

    if (!existingAdmin) {
        const hash = bcrypt.hashSync(adminPassword, 12);

        db.prepare(`
            INSERT INTO users (email, password, is_admin)
            VALUES (?, ?, 1)
        `).run(adminEmail, hash);

        console.log("Administrator account created.");
    } else {
        db.prepare(
            "UPDATE users SET is_admin = 1 WHERE email = ?"
        ).run(adminEmail);
    }
} else {
    console.warn(
        "ADMIN_EMAIL or ADMIN_PASSWORD is missing or invalid."
    );
}

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            mediaSrc: ["'self'", "https:", "blob:"],
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameAncestors: ["'none'"]
        }
    }
}));

app.use(express.json({ limit: "30kb" }));
app.use(express.urlencoded({
    extended: false,
    limit: "30kb"
}));

app.use(session({
    name: "xxxvideo.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    store: new SQLiteStore({
        db: "sessions.sqlite",
        dir: path.dirname(DB_PATH)
    }),

    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
}));

app.use(express.static(path.join(__dirname, "public")));

/* =========================
   SECURITY MIDDLEWARE
========================= */

const loginAttempts = new Map();

function rateLimitLogin(req, res, next) {
    const key = req.ip || "unknown";
    const now = Date.now();

    let entry = loginAttempts.get(key);

    if (!entry || entry.until <= now) {
        entry = {
            count: 0,
            until: now + 15 * 60 * 1000
        };

        loginAttempts.set(key, entry);
    }

    if (entry.count >= 10) {
        return res.status(429).json({
            error: "Too many attempts. Please try again later."
        });
    }

    entry.count++;
    next();
}

function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            error: "Please sign in first."
        });
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user || !req.session.user.is_admin) {
        return res.status(403).json({
            error: "Administrator access required."
        });
    }

    next();
}

function safeUser(user) {
    return {
        id: user.id,
        email: user.email,
        is_admin: Boolean(user.is_admin)
    };
}

function validHttpUrl(value) {
    try {
        const url = new URL(value);

        return (
            url.protocol === "https:" ||
            url.protocol === "http:"
        );
    } catch {
        return false;
    }
}

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        app: "XXX VIDEO"
    });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", (req, res) => {
    res.json({
        user: req.session.user || null
    });
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", rateLimitLogin, async (req, res) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        const password = String(req.body.password || "");
        const adultConfirmed = req.body.adultConfirmed === true;

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({
                error: "Enter a valid email address."
            });
        }

        if (password.length < 10 || password.length > 128) {
            return res.status(400).json({
                error: "Password must be 10 to 128 characters."
            });
        }

        if (!adultConfirmed) {
            return res.status(400).json({
                error: "Please confirm that you meet the legal age requirement."
            });
        }

        const hash = await bcrypt.hash(password, 12);

        let result;

        try {
            result = db.prepare(`
                INSERT INTO users (email, password)
                VALUES (?, ?)
            `).run(email, hash);
        } catch (error) {
            if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
                return res.status(409).json({
                    error: "This email is already registered."
                });
            }

            throw error;
        }

        const user = db.prepare(`
            SELECT id, email, is_admin
            FROM users
            WHERE id = ?
        `).get(result.lastInsertRowid);

        req.session.regenerate((error) => {
            if (error) {
                return res.status(500).json({
                    error: "Could not create your session."
                });
            }

            req.session.user = safeUser(user);

            res.status(201).json({
                user: req.session.user
            });
        });

    } catch (error) {
        console.error("Registration error:", error.message);

        res.status(500).json({
            error: "Registration failed."
        });
    }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", rateLimitLogin, async (req, res) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        const password = String(req.body.password || "");

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE email = ?
        `).get(email);

        if (
            !user ||
            !(await bcrypt.compare(password, user.password))
        ) {
            return res.status(401).json({
                error: "Incorrect email or password."
            });
        }

        req.session.regenerate((error) => {
            if (error) {
                return res.status(500).json({
                    error: "Could not create your session."
                });
            }

            req.session.user = safeUser(user);

            res.json({
                user: req.session.user
            });
        });

    } catch (error) {
        console.error("Login error:", error.message);

        res.status(500).json({
            error: "Login failed."
        });
    }
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            return res.status(500).json({
                error: "Logout failed."
            });
        }

        res.clearCookie("xxxvideo.sid");

        res.json({
            success: true
        });
    });
});

/* =========================
   VIDEO SEARCH
========================= */

app.get("/api/videos", (req, res) => {
    const search = String(req.query.search || "")
        .trim()
        .slice(0, 100);

    const category = String(req.query.category || "")
        .trim()
        .slice(0, 60);

    let sql = `
        SELECT
            id,
            title,
            description,
            category,
            thumbnail,
            video_url
        FROM videos
        WHERE active = 1
    `;

    const params = [];

    if (search) {
        sql += `
            AND (
                title LIKE ?
                OR description LIKE ?
            )
        `;

        params.push(
            "%" + search + "%",
            "%" + search + "%"
        );
    }

    if (category && category !== "All") {
        sql += " AND category = ?";
        params.push(category);
    }

    sql += " ORDER BY id DESC LIMIT 200";

    const videos = db.prepare(sql).all(...params);

    res.json({ videos });
});

/* =========================
   VIDEO CATEGORIES
========================= */

app.get("/api/categories", (req, res) => {
    const categories = db.prepare(`
        SELECT DISTINCT category
        FROM videos
        WHERE active = 1
        ORDER BY category
    `).all().map(row => row.category);

    res.json({
        categories: ["All", ...categories]
    });
});

/* =========================
   ADD OR REMOVE FAVORITES
========================= */

app.post("/api/favorites/:id", requireAuth, (req, res) => {
    const videoId = Number(req.params.id);

    if (!Number.isSafeInteger(videoId)) {
        return res.status(400).json({
            error: "Invalid video ID."
        });
    }

    const video = db.prepare(`
        SELECT id
        FROM videos
        WHERE id = ? AND active = 1
    `).get(videoId);

    if (!video) {
        return res.status(404).json({
            error: "Video not found."
        });
    }

    const userId = req.session.user.id;

    const existing = db.prepare(`
        SELECT 1
        FROM favorites
        WHERE user_id = ? AND video_id = ?
    `).get(userId, videoId);

    if (existing) {
        db.prepare(`
            DELETE FROM favorites
            WHERE user_id = ? AND video_id = ?
        `).run(userId, videoId);

        return res.json({
            favorited: false
        });
    }

    db.prepare(`
        INSERT OR IGNORE INTO favorites (user_id, video_id)
        VALUES (?, ?)
    `).run(userId, videoId);

    res.json({
        favorited: true
    });
});

/* =========================
   GET FAVORITES
========================= */

app.get("/api/favorites", requireAuth, (req, res) => {
    const videos = db.prepare(`
        SELECT
            v.id,
            v.title,
            v.description,
            v.category,
            v.thumbnail,
            v.video_url
        FROM videos v
        JOIN favorites f ON f.video_id = v.id
        WHERE f.user_id = ? AND v.active = 1
        ORDER BY v.id DESC
    `).all(req.session.user.id);

    res.json({ videos });
});

/* =========================
   WATCH HISTORY
========================= */

app.post("/api/history/:id", requireAuth, (req, res) => {
    const videoId = Number(req.params.id);

    if (!Number.isSafeInteger(videoId)) {
        return res.status(400).json({
            error: "Invalid video ID."
        });
    }

    const video = db.prepare(`
        SELECT id
        FROM videos
        WHERE id = ? AND active = 1
    `).get(videoId);

    if (!video) {
        return res.status(404).json({
            error: "Video not found."
        });
    }

    db.prepare(`
        INSERT INTO history (user_id, video_id, watched_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, video_id)
        DO UPDATE SET watched_at = CURRENT_TIMESTAMP
    `).run(req.session.user.id, videoId);

    res.json({
        success: true
    });
});

/* =========================
   GET WATCH HISTORY
========================= */

app.get("/api/history", requireAuth, (req, res) => {
    const videos = db.prepare(`
        SELECT
            v.id,
            v.title,
            v.description,
            v.category,
            v.thumbnail,
            v.video_url,
            h.watched_at
        FROM history h
        JOIN videos v ON v.id = h.video_id
        WHERE h.user_id = ? AND v.active = 1
        ORDER BY h.watched_at DESC
        LIMIT 100
    `).all(req.session.user.id);

    res.json({ videos });
});

/* =========================
   ADMIN: LIST VIDEOS
========================= */

app.get("/api/admin/videos", requireAdmin, (req, res) => {
    const videos = db.prepare(`
        SELECT *
        FROM videos
        ORDER BY id DESC
        LIMIT 500
    `).all();

    res.json({ videos });
});

/* =========================
   ADMIN: ADD VIDEO
========================= */

app.post("/api/admin/videos", requireAdmin, (req, res) => {
    const title = String(req.body.title || "")
        .trim()
        .slice(0, 150);

    const description = String(req.body.description || "")
        .trim()
        .slice(0, 2000);

    const category = String(req.body.category || "Other")
        .trim()
        .slice(0, 60);

    const thumbnail = String(req.body.thumbnail || "").trim();
    const videoUrl = String(req.body.video_url || "").trim();

    if (!title || !videoUrl || !validHttpUrl(videoUrl)) {
        return res.status(400).json({
            error: "A title and valid HTTP/HTTPS video URL are required."
        });
    }

    if (thumbnail && !validHttpUrl(thumbnail)) {
        return res.status(400).json({
            error: "Thumbnail must be a valid HTTP/HTTPS URL."
        });
    }

    const result = db.prepare(`
        INSERT INTO videos (
            title,
            description,
            category,
            thumbnail,
            video_url
        )
        VALUES (?, ?, ?, ?, ?)
    `).run(
        title,
        description,
        category || "Other",
        thumbnail,
        videoUrl
    );

    res.status(201).json({
        success: true,
        id: result.lastInsertRowid
    });
});

/* =========================
   ADMIN: HIDE OR PUBLISH VIDEO
========================= */

app.patch("/api/admin/videos/:id", requireAdmin, (req, res) => {
    const videoId = Number(req.params.id);
    const active = req.body.active;

    if (
        !Number.isSafeInteger(videoId) ||
        typeof active !== "boolean"
    ) {
        return res.status(400).json({
            error: "Invalid request."
        });
    }

    const result = db.prepare(`
        UPDATE videos
        SET active = ?
        WHERE id = ?
    `).run(active ? 1 : 0, videoId);

    if (!result.changes) {
        return res.status(404).json({
            error: "Video not found."
        });
    }

    res.json({
        success: true
    });
});

/* =========================
   ADMIN: DELETE VIDEO
========================= */

app.delete("/api/admin/videos/:id", requireAdmin, (req, res) => {
    const videoId = Number(req.params.id);

    if (!Number.isSafeInteger(videoId)) {
        return res.status(400).json({
            error: "Invalid video ID."
        });
    }

    const result = db.prepare(`
        DELETE FROM videos
        WHERE id = ?
    `).run(videoId);

    if (!result.changes) {
        return res.status(404).json({
            error: "Video not found."
        });
    }

    res.json({
        success: true
    });
});

/* =========================
   WEBSITE ROUTE
========================= */

app.get("*", (req, res, next) => {
    if (req.path.startsWith("/api/")) {
        return res.status(404).json({
            error: "API endpoint not found."
        });
    }

    res.sendFile(
        path.join(__dirname, "public", "index.html"),
        error => {
            if (error) next(error);
        }
    );
});

/* =========================
   ERROR HANDLER
========================= */

app.use((error, req, res, next) => {
    console.error("Server error:", error.message);

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        error: "An internal server error occurred."
    });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
    console.log(`XXX VIDEO is running on port ${PORT}`);
});
