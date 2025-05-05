<?php
session_start();
if (!isset($_SESSION['user_id'])) {
  header('Location: user_login.php');
  exit;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ranger Login - AI Wildlife System</title>
  <link rel="stylesheet" href="login.css">
</head>

<body>

  <div class="login-container">
    <h1>Ranger Login</h1>

    <form id="login-form">
      <input type="text" id="username" placeholder="Username" required />

      <div style="position: relative;">
        <input type="password" id="password" placeholder="Password" required />
        <span id="togglePassword" 
              style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); cursor: pointer;">
          👁️
        </span>
      </div>

      <button type="submit">Login</button>
    </form>

    <p id="login-error-msg" style="color: red;"></p>
    <p>Don't have an account? <a href="signup.html">Sign up here</a></p>
  </div>

  <script>
    document.getElementById('login-form').addEventListener('submit', async e => {
      e.preventDefault();
      const u = document.getElementById('username').value.trim();
      const p = document.getElementById('password').value;

      const res = await fetch('login.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username: u, password: p })
      });

      const json = await res.json();

      if (res.ok) {
        location.href = 'index.php'; // Redirect to dashboard
      } else {
        document.getElementById('login-error-msg').textContent = json.error;
      }
    });

    // Eye toggle for Password
    document.getElementById('togglePassword').addEventListener('click', function () {
      const passwordField = document.getElementById('password');
      const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
      passwordField.setAttribute('type', type);
      this.textContent = type === 'password' ? '👁️' : '🙈';
    });
  </script>

</body>

</html>
