const API_BASE_URL = 'http://localhost:8000';

// Tworzenie wiadomości
document.getElementById('message-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const content = document.getElementById('message-content').value;
    const privateKey = document.getElementById('private-key').value;
  
    const response = await fetch(`${API_BASE_URL}/message/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${localStorage.getItem('authToken')}`,
      },
      body: JSON.stringify({ content, private_key: privateKey }),
    });
  
    const result = await response.json();
    document.getElementById('message-result').innerText = response.ok
      ? 'Wiadomość utworzona!'
      : `Błąd: ${JSON.stringify(result)}`;
  });
  
  // Pobieranie wiadomości
  document.getElementById('fetch-messages').addEventListener('click', async () => {
    const response = await fetch(`${API_BASE_URL}/messages/`);
    const messages = await response.json();
  
    const messagesList = document.getElementById('messages-list');
    messagesList.innerHTML = '';
    messages.forEach((msg) => {
      const messageDiv = document.createElement('div');
      messageDiv.innerHTML = `<p><strong>${msg.user}</strong>: ${msg.content}</p><p>Podpis: ${msg.signature}</p>`;
      messagesList.appendChild(messageDiv);
    });
  });
  