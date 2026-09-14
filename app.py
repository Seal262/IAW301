import sqlite3
from fastapi import FastAPI, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse
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

cursor.executemany("""
    INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
""", [
    ("admin", "123"),
    ("user1", "456"),
    ("user2", "password3")
])

connection.commit()
cursor.close()
connection.close()

app = FastAPI(title="iaw301_webapp")


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
        </body>
    </html>
    """)


@app.post("/login")
def login(response: Response, username: str = Form(...), password: str = Form(...)):
    conn = sqlite3.connect(database=db_name)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, password))
    row = cur.fetchone()
    cur.close()
    conn.close()

    if row:
        response.set_cookie(key="username", value=username, httponly=True)
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
        return HTMLResponse(content="""
        <html>
            <body>
                <h1>Login thất bại</h1>
                <p>Sai username hoặc password.</p>
                <a href="/login-form">Thử lại</a>
            </body>
        </html>
        """, status_code=401)


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login-form")
    response.delete_cookie(key="username")
    return response


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