<?php
header('Content-Type: application/json');

// 1. Get JSON body
$body = json_decode(file_get_contents('php://input'), true);
$username = trim($body['username'] ?? '');
$password = $body['password'] ?? '';

// 2. Validation
if (!$username || !$password) {
  http_response_code(400);
  echo json_encode(['error'=>'Missing username or password']);
  exit;
}

if (!preg_match('/^[a-zA-Z0-9_]{5,20}$/', $username)) {
  http_response_code(400);
  echo json_encode(['error'=>'Username must be 5-20 characters and alphanumeric']);
  exit;
}

if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/', $password)) {
  http_response_code(400);
  echo json_encode(['error'=>'Password must be at least 8 characters and include uppercase, lowercase, number, and special character']);
  exit;
}

// 3. Connect to database
$conn = new mysqli('localhost','root','', 'my_app');
if ($conn->connect_error) {
  http_response_code(500);
  echo json_encode(['error'=>'DB connect failed']);
  exit;
}

// 4. Check if username exists
$stmt = $conn->prepare('SELECT id FROM users WHERE username = ?');
$stmt->bind_param('s', $username);
$stmt->execute();
$stmt->store_result();
if ($stmt->num_rows) {
  http_response_code(409);
  echo json_encode(['error'=>'Username already taken']);
  exit;
}

// 5. Hash password and insert
$hash = password_hash($password, PASSWORD_DEFAULT);
$stmt = $conn->prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
$stmt->bind_param('ss', $username, $hash);

if ($stmt->execute()) {
  echo json_encode(['success'=>'Signup successful']);
} else {
  http_response_code(500);
  echo json_encode(['error'=>'Insert failed']);
}
?>
