const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const btnBg = document.getElementById("btn-bg");
const statusDiv = document.getElementById("status-message");

const [tabLogin, tabRegister] = document.querySelectorAll('[role="tab"]');

function showRegister() {
    loginForm.style.left = "-400px";
    registerForm.style.left = "50px";
    btnBg.style.left = "110px";
    statusDiv.style.display = "none";
    tabLogin.setAttribute("aria-selected", "false");
    tabRegister.setAttribute("aria-selected", "true");
}

function showLogin() {
    loginForm.style.left = "50px";
    registerForm.style.left = "450px";
    btnBg.style.left = "0";
    statusDiv.style.display = "none";
    tabLogin.setAttribute("aria-selected", "true");
    tabRegister.setAttribute("aria-selected", "false");
}

function showMessage(text, isSuccess) {
    statusDiv.textContent = text;
    statusDiv.style.display = "block";
    statusDiv.style.color = isSuccess ? "#155724" : "#721c24";
    statusDiv.style.backgroundColor = isSuccess ? "#d4edda" : "#f8d7da";
    statusDiv.style.borderColor = isSuccess ? "#c3e6cb" : "#f5c6cb";
}

async function postJSON(url, payload) {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    return { response, data };
}

// Registration
registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("reg-username").value.trim();
    const password = document.getElementById("reg-password").value;

    try {
        const { response, data } = await postJSON("http://localhost:8080/api/register", {
            username,
            password,
        });

        showMessage(data.message || "Registration failed.", response.ok);

        if (response.ok) {
            setTimeout(showLogin, 2000);
        }
    } catch {
        showMessage("Server connection failed.", false);
    }
});

// Login
loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;

    try {
        const { response, data } = await postJSON("http://localhost:8080/api/login", {
            username,
            password,
        });

        showMessage(data.message || "Login failed.", response.ok);

        if (response.ok) {
            // In a real app, redirect to dashboard.
            // window.location.href = "/dashboard";
        }
    } catch {
        showMessage("Server connection failed.", false);
    }
});

// Default state
showLogin();

