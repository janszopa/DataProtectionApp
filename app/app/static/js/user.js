const API_BASE_URL = 'http://localhost:8000';

// Rejestracja użytkownika
document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('register-username').value;
  const email = document.getElementById('register-email').value;
  const password = document.getElementById('register-password').value;

  const response = await fetch(`${API_BASE_URL}/register/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password }),
  });

  const result = await response.json();
  document.getElementById('register-result').innerText = response.ok
    ? 'Rejestracja zakończona sukcesem!'
    : `Błąd: ${JSON.stringify(result)}`;
});

// Logowanie użytkownika
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;

  const response = await fetch(`${API_BASE_URL}/login/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (response.ok) {
    const result = await response.json();
    localStorage.setItem('authToken', result.token);
    document.getElementById('login-result').innerText = 'Zalogowano pomyślnie!';
  } else {
    document.getElementById('login-result').innerText = 'Nieprawidłowe dane logowania.';
  }
});
