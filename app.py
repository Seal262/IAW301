import sqlite3
import time
import re
import secrets
import jwt
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Form, Response, Request, Depends, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel
import uvicorn

db_name = "iaw301"

connection = sqlite3.connect(database=db_name)
cursor = connection.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
""")

connection.commit()
cursor.close()
connection.close()

app = FastAPI(title="iaw301_webapp")


# =========================================================
# CẤU HÌNH CHUNG
# =========================================================

# --- Session (cookie) ---
# session_id (random, không đoán được) -> username
SESSION_STORE: dict[str, str] = {}
SESSION_COOKIE_NAME = "session_id"

# --- JWT ---
JWT_SECRET = "iaw301-jwt-secret-change-me"   # trong thực tế nên lấy từ biến môi trường
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 30

# --- Chống brute-force theo IP: Exponential Backoff ---
# ip -> {"fail_count": int, "next_allowed_at": float(epoch)}
LOGIN_ATTEMPTS: dict[str, dict] = {}
BACKOFF_BASE_SECONDS = 20     # lần sai đầu tiên: chờ 20s
BACKOFF_MAX_SECONDS = 5 * 60  # chặn tăng dần nhưng không vượt quá 5 phút

# --- Rate limit theo IP: thuật toán Leaky Bucket ---
# Mỗi IP có 1 "xô" (bucket) sức chứa RATE_LIMIT_CAPACITY request.
# Mỗi request tới sẽ đổ thêm 1 đơn vị vào xô; xô luôn "rò rỉ" (leak) dần theo
# thời gian với tốc độ RATE_LIMIT_LEAK_PER_SEC đơn vị/giây. Nếu xô đầy (request
# đến nhanh hơn tốc độ rò) thì request bị từ chối (429) cho tới khi xô vơi bớt.
# ip -> {"level": float, "last_check": float(epoch)}
RATE_LIMIT_BUCKETS: dict[str, dict] = {}
RATE_LIMIT_CAPACITY = 10        # sức chứa tối đa của xô: chịu được burst 10 request
RATE_LIMIT_LEAK_PER_SEC = 2     # tốc độ rò: trung bình cho phép ~2 request/giây


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


# =========================================================
# HÀM HỖ TRỢ: LẤY IP THẬT CỦA CLIENT
# =========================================================
def get_client_ip(request: Request) -> str:
    """
    Luôn lấy IP từ kết nối TCP thật (request.client.host) do chính server
    (uvicorn) ghi nhận khi bắt tay kết nối — KHÔNG đọc từ bất kỳ header nào
    do client tự gửi lên (X-Forwarded-For, X-Real-IP...) vì các header này
    người dùng có thể tự chỉnh sửa/giả mạo trong request của họ.
    Nhờ vậy client không thể "đổi IP" của chính mình để né chặn brute-force.
    """
    return request.client.host if request.client else "unknown"


def is_ip_blocked(ip: str) -> bool:
    record = LOGIN_ATTEMPTS.get(ip)
    if not record:
        return False
    return time.time() < record.get("next_allowed_at", 0)


def get_remaining_wait_seconds(ip: str) -> int:
    """Số giây còn lại phải chờ trước khi được đăng nhập lại."""
    record = LOGIN_ATTEMPTS.get(ip)
    if not record:
        return 0
    remaining = record.get("next_allowed_at", 0) - time.time()
    return max(0, round(remaining))


def register_failed_attempt(ip: str) -> int:
    """
    Exponential Backoff: mỗi lần sai, thời gian phải chờ trước lần thử tiếp theo
    tăng gấp đôi so với lần trước — 20s, 40s, 80s, 160s, ... (tối đa BACKOFF_MAX_SECONDS).
    Trả về số giây phải chờ lần này để hiển thị cho client biết.
    """
    record = LOGIN_ATTEMPTS.setdefault(ip, {"fail_count": 0, "next_allowed_at": 0})
    record["fail_count"] += 1
    wait_seconds = min(BACKOFF_BASE_SECONDS * (2 ** (record["fail_count"] - 1)), BACKOFF_MAX_SECONDS)
    record["next_allowed_at"] = time.time() + wait_seconds
    return wait_seconds


def reset_attempts(ip: str) -> None:
    if ip in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS.pop(ip, None)


# =========================================================
# HÀM HỖ TRỢ: RATE LIMIT (LEAKY BUCKET)
# =========================================================
def allow_request(ip: str) -> bool:
    """
    Trả về True nếu request được phép đi qua, False nếu bị chặn vì "xô" đã đầy.
    Mỗi lần gọi: tính thời gian đã trôi qua từ lần check trước -> rò bớt
    (giảm level) theo tốc độ RATE_LIMIT_LEAK_PER_SEC, sau đó mới cộng thêm
    1 đơn vị cho request hiện tại nếu còn chỗ trống.
    """
    now = time.time()
    bucket = RATE_LIMIT_BUCKETS.setdefault(ip, {"level": 0.0, "last_check": now})

    elapsed = now - bucket["last_check"]
    leaked = elapsed * RATE_LIMIT_LEAK_PER_SEC
    bucket["level"] = max(0.0, bucket["level"] - leaked)
    bucket["last_check"] = now

    if bucket["level"] + 1 > RATE_LIMIT_CAPACITY:
        return False

    bucket["level"] += 1
    return True


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    ip = get_client_ip(request)
    if not allow_request(ip):
        return JSONResponse(
            content={"detail": "Bạn đang gửi request quá nhanh (rate limit). Vui lòng thử lại sau."},
            status_code=429,
        )
    return await call_next(request)


# =========================================================
# HÀM HỖ TRỢ: VALIDATE PASSWORD
# =========================================================
def validate_password(password: str) -> str | None:
    """
    Trả về None nếu password hợp lệ, ngược lại trả về chuỗi mô tả lỗi.
    Yêu cầu: tối thiểu 6 ký tự, có chữ hoa, chữ thường, số và ký tự đặc biệt.
    """
    if len(password) < 6:
        return "Password phải có ít nhất 6 ký tự."
    if not re.search(r"[A-Z]", password):
        return "Password phải chứa ít nhất 1 chữ hoa."
    if not re.search(r"[a-z]", password):
        return "Password phải chứa ít nhất 1 chữ thường."
    if not re.search(r"\d", password):
        return "Password phải chứa ít nhất 1 chữ số."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password phải chứa ít nhất 1 ký tự đặc biệt (!@#$%...)."
    return None


# =========================================================
# HÀM HỖ TRỢ: JWT
# =========================================================
def create_jwt_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token đã hết hạn")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token không hợp lệ")


def get_current_user_jwt(authorization: str = Header(None)) -> str:
    """Dependency: đọc header 'Authorization: Bearer <token>'."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thiếu Bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    return decode_jwt_token(token)


def get_current_user_session(request: Request) -> str:
    """Dependency: đọc cookie session_id, tra trong SESSION_STORE."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    username = SESSION_STORE.get(session_id) if session_id else None
    if not username:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập hoặc session đã hết hạn")
    return username


# =========================================================
# ROUTES CƠ BẢN
# =========================================================
@app.get("/ping")
def ping():
    return "pong"


@app.get("/login-form")
def get_login_form():
    return HTMLResponse(content="""
    <html>
        <head>
            <title>Login</title>
        </head>
        <meta charset="UTF-8">
        <body>
            <h1>Login</h1>
            <form action="/login" method="post">
                <label for="username">Username/Email:</label>
                <input type="text" id="username" name="username" required><br><br>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required><br><br>
                <input type="submit" value="Login">
            </form>
            <p>Chưa có tài khoản? <a href="/register-form">Đăng ký</a></p>
        </body>
    </html>
    """)


@app.get("/register-form")
def get_register_form():
    return HTMLResponse(content="""
    <html>
        <head>
            <title>Register</title>
            <meta charset="UTF-8">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: #f2f4f8;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .card {
                    background: #fff;
                    padding: 32px 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 16px rgba(0,0,0,0.1);
                    width: 320px;
                }
                h1 { margin-top: 0; font-size: 22px; }
                label { display: block; margin-top: 14px; font-size: 14px; color: #333; }
                input {
                    width: 100%;
                    padding: 8px 10px;
                    margin-top: 6px;
                    border: 1px solid #ccc;
                    border-radius: 6px;
                    box-sizing: border-box;
                    font-size: 14px;
                }
                button {
                    margin-top: 20px;
                    width: 100%;
                    padding: 10px;
                    border: none;
                    border-radius: 6px;
                    background: #2563eb;
                    color: #fff;
                    font-size: 15px;
                    cursor: pointer;
                }
                button:disabled { background: #93b4f0; cursor: not-allowed; }
                #message {
                    margin-top: 14px;
                    font-size: 14px;
                    min-height: 18px;
                }
                #message.success { color: #16a34a; }
                #message.error { color: #dc2626; }
                a { color: #2563eb; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Đăng ký</h1>
                <form id="registerForm">
                    <label for="username">Username/Email</label>
                    <input type="text" id="username" name="username" required>
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                    <p style="font-size:12px; color:#666; margin:6px 0 0;">
                        Tối thiểu 6 ký tự, gồm chữ hoa, chữ thường, số và ký tự đặc biệt.
                    </p>
                    <button type="submit" id="submitBtn">Đăng ký</button>
                    <div id="message"></div>
                </form>
                <p style="margin-top:18px; font-size:14px;">
                    Đã có tài khoản? <a href="/login-form">Đăng nhập</a>
                </p>
            </div>

            <script>
                const form = document.getElementById("registerForm");
                const messageEl = document.getElementById("message");
                const submitBtn = document.getElementById("submitBtn");

                form.addEventListener("submit", async (e) => {
                    e.preventDefault();

                    const username = document.getElementById("username").value.trim();
                    const password = document.getElementById("password").value;

                    if (password.length < 6 ||
                        !/[A-Z]/.test(password) ||
                        !/[a-z]/.test(password) ||
                        !/\\d/.test(password) ||
                        !/[^A-Za-z0-9]/.test(password)) {
                        messageEl.textContent = "Password cần tối thiểu 6 ký tự, gồm chữ hoa, chữ thường, số và ký tự đặc biệt.";
                        messageEl.className = "error";
                        return;
                    }

                    submitBtn.disabled = true;
                    messageEl.textContent = "Đang xử lý...";
                    messageEl.className = "";

                    try {
                        const res = await fetch("/register", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ username, password })
                        });
                        const data = await res.json();

                        if (res.ok) {
                            messageEl.textContent = data.message;
                            messageEl.className = "success";
                            form.reset();
                        } else {
                            messageEl.textContent = data.message;
                            messageEl.className = "error";
                        }
                    } catch (err) {
                        messageEl.textContent = "Không kết nối được server.";
                        messageEl.className = "error";
                    } finally {
                        submitBtn.disabled = false;
                    }
                });
            </script>
        </body>
    </html>
    """)


@app.post("/register")
def register(data: RegisterRequest):
    error = validate_password(data.password)
    if error:
        return JSONResponse(content={"message": error}, status_code=400)

    conn = sqlite3.connect(database=db_name)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (data.username, data.password))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    finally:
        cur.close()
        conn.close()

    if success:
        return JSONResponse(content={"message": f"Tài khoản {data.username} đã được tạo thành công."})
    else:
        return JSONResponse(
            content={"message": "Username này đã tồn tại, vui lòng chọn username khác."},
            status_code=409
        )


# =========================================================
# LOGIN — SESSION (COOKIE) + CHỐNG BRUTE-FORCE THEO IP
# =========================================================
@app.post("/login")
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    client_ip = get_client_ip(request)

    if is_ip_blocked(client_ip):
        wait = get_remaining_wait_seconds(client_ip)
        return HTMLResponse(content=f"""
        <html>
            <body>
                <h1>Tạm khoá</h1>
                <p>Bạn đăng nhập sai, vui lòng thử lại sau {wait} giây.</p>
                <a href="/login-form">Quay lại</a>
            </body>
        </html>
        """, status_code=429)

    conn = sqlite3.connect(database=db_name)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, password))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        reset_attempts(client_ip)

        # Tạo session ngẫu nhiên, KHÔNG lưu trực tiếp username vào cookie
        session_id = secrets.token_hex(32)
        SESSION_STORE[session_id] = username
        response.set_cookie(key=SESSION_COOKIE_NAME, value=session_id, httponly=True)

        return HTMLResponse(content=f"""
        <html>
            <body>
                <h1>Login thành công</h1>
                <p>Xin chào, {username}!</p>
                <a href="/logout">Đăng xuất</a>
            </body>
        </html>
        """)
    else:
        wait = register_failed_attempt(client_ip)
        return HTMLResponse(content=f"""
        <html>
            <body>
                <h1>Login thất bại</h1>
                <p>Sai username hoặc password. Vui lòng thử lại sau {wait} giây.</p>
                <a href="/login-form">Thử lại</a>
            </body>
        </html>
        """, status_code=401)


@app.get("/logout")
def logout(request: Request):
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if session_id:
        SESSION_STORE.pop(session_id, None)

    response = RedirectResponse(url="/login-form")
    response.delete_cookie(key=SESSION_COOKIE_NAME)
    return response


@app.get("/me")
def get_me(username: str = Depends(get_current_user_session)):
    """Ví dụ route được bảo vệ bằng session cookie."""
    return {"username": username, "auth_type": "session"}


# =========================================================
# LOGIN — JWT (dùng song song với session, không dùng cookie)
# =========================================================
@app.get("/login-jwt-form")
def get_login_jwt_form():
    return HTMLResponse(content="""
    <html>
        <head>
            <title>Login JWT</title>
            <meta charset="UTF-8">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: #f2f4f8;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    margin: 0;
                }
                .card {
                    background: #fff;
                    padding: 32px 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 16px rgba(0,0,0,0.1);
                    width: 400px;
                }
                h1 { margin-top: 0; font-size: 22px; }
                label { display: block; margin-top: 14px; font-size: 14px; color: #333; }
                input {
                    width: 100%;
                    padding: 8px 10px;
                    margin-top: 6px;
                    border: 1px solid #ccc;
                    border-radius: 6px;
                    box-sizing: border-box;
                    font-size: 14px;
                }
                button {
                    margin-top: 20px;
                    width: 100%;
                    padding: 10px;
                    border: none;
                    border-radius: 6px;
                    background: #2563eb;
                    color: #fff;
                    font-size: 15px;
                    cursor: pointer;
                }
                button.secondary { background: #6b7280; margin-top: 10px; }
                #message { margin-top: 14px; font-size: 14px; min-height: 18px; }
                #message.success { color: #16a34a; }
                #message.error { color: #dc2626; }
                #tokenBox {
                    margin-top: 14px;
                    padding: 10px;
                    background: #f2f4f8;
                    border-radius: 6px;
                    word-break: break-all;
                    font-size: 12px;
                    font-family: monospace;
                    display: none;
                }
                #profileResult {
                    margin-top: 10px;
                    font-size: 13px;
                    color: #333;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Login JWT (test nhanh)</h1>
                <form id="loginForm">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                    <button type="submit" id="submitBtn">Lấy token</button>
                    <div id="message"></div>
                    <div id="tokenBox"></div>
                    <button type="button" id="copyBtn" class="secondary" style="display:none;">Copy token</button>
                    <button type="button" id="testProfileBtn" class="secondary" style="display:none;">Test /profile với token này</button>
                    <div id="profileResult"></div>
                </form>
            </div>

            <script>
                const form = document.getElementById("loginForm");
                const messageEl = document.getElementById("message");
                const submitBtn = document.getElementById("submitBtn");
                const tokenBox = document.getElementById("tokenBox");
                const copyBtn = document.getElementById("copyBtn");
                const testProfileBtn = document.getElementById("testProfileBtn");
                const profileResult = document.getElementById("profileResult");

                function getToken() {
                    return sessionStorage.getItem("jwt_token") || "";
                }

                function saveToken(token) {
                    // Lưu token vào sessionStorage của trình duyệt (mất khi đóng tab,
                    // còn khi F5/refresh vẫn giữ nguyên) — đây là bước "client save".
                    sessionStorage.setItem("jwt_token", token);
                }

                function showToken(token) {
                    tokenBox.textContent = token;
                    tokenBox.style.display = "block";
                    copyBtn.style.display = "block";
                    testProfileBtn.style.display = "block";
                }

                // Nếu trang được load lại (F5) mà sessionStorage đã có token cũ, hiện luôn ra
                window.addEventListener("DOMContentLoaded", () => {
                    const existing = getToken();
                    if (existing) {
                        messageEl.textContent = "Đang dùng token đã lưu trong sessionStorage.";
                        messageEl.className = "success";
                        showToken(existing);
                    }
                });

                form.addEventListener("submit", async (e) => {
                    e.preventDefault();
                    const username = document.getElementById("username").value.trim();
                    const password = document.getElementById("password").value;

                    submitBtn.disabled = true;
                    messageEl.textContent = "Đang xử lý...";
                    messageEl.className = "";
                    tokenBox.style.display = "none";
                    copyBtn.style.display = "none";
                    testProfileBtn.style.display = "none";
                    profileResult.textContent = "";

                    try {
                        const res = await fetch("/login-jwt", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ username, password })
                        });
                        const data = await res.json();

                        if (res.ok) {
                            saveToken(data.access_token);
                            messageEl.textContent = "Lấy token thành công! Đã lưu vào sessionStorage.";
                            messageEl.className = "success";
                            showToken(data.access_token);
                        } else {
                            messageEl.textContent = data.detail || "Đăng nhập thất bại.";
                            messageEl.className = "error";
                        }
                    } catch (err) {
                        messageEl.textContent = "Không kết nối được server.";
                        messageEl.className = "error";
                    } finally {
                        submitBtn.disabled = false;
                    }
                });

                copyBtn.addEventListener("click", () => {
                    navigator.clipboard.writeText(getToken());
                    copyBtn.textContent = "Đã copy!";
                    setTimeout(() => { copyBtn.textContent = "Copy token"; }, 1500);
                });

                testProfileBtn.addEventListener("click", async () => {
                    profileResult.textContent = "Đang gọi /profile...";
                    try {
                        // Lấy token từ sessionStorage rồi đính kèm vào header Authorization: Bearer
                        const res = await fetch("/profile", {
                            headers: { "Authorization": "Bearer " + getToken() }
                        });
                        const data = await res.json();
                        profileResult.textContent = "/profile trả về: " + JSON.stringify(data);
                    } catch (err) {
                        profileResult.textContent = "Lỗi khi gọi /profile.";
                    }
                });
            </script>
        </body>
    </html>
    """)


@app.post("/login-jwt")
def login_jwt(request: Request, data: LoginRequest):
    client_ip = get_client_ip(request)

    if is_ip_blocked(client_ip):
        wait = get_remaining_wait_seconds(client_ip)
        raise HTTPException(status_code=429, detail=f"Vui lòng thử lại sau {wait} giây.")

    conn = sqlite3.connect(database=db_name)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ? AND password = ?", (data.username, data.password))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        wait = register_failed_attempt(client_ip)
        raise HTTPException(status_code=401, detail=f"Sai username hoặc password. Vui lòng thử lại sau {wait} giây.")

    reset_attempts(client_ip)
    token = create_jwt_token(data.username)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/profile")
def get_profile(username: str = Depends(get_current_user_jwt)):
    """Ví dụ route được bảo vệ bằng JWT (gửi header Authorization: Bearer <token>)."""
    return {"username": username, "auth_type": "jwt"}


# =========================================================
# CÁC ROUTE CÒN LẠI
# =========================================================
@app.get("/all")
def get_all_users():
    conn = sqlite3.connect(database=db_name)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password FROM users")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    rows_html = "".join(
        f"<tr><td>{id_}</td><td>{username}</td><td>{password}</td></tr>"
        for id_, username, password in rows
    )

    return HTMLResponse(content=f"""
    <html>
        <head>
            <title>All Users</title>
            <style>
                table {{ border-collapse: collapse; }}
                th, td {{ border: 1px solid #333; padding: 6px 12px; }}
            </style>
        </head>
        <body>
            <h1>Bảng thông tin user</h1>
            <table>
                <tr><th>id</th><th>username/email</th><th>password</th></tr>
                {rows_html}
            </table>
        </body>
    </html>
    """)


@app.get("/")
def root():
    return RedirectResponse(url="/login-form")


if __name__ == "__main__":
    uvicorn.run(app=app, host="127.0.0.1", port=8888)