
<?php
session_start();
if (!isset($_SESSION['user_id'])) {
  header('Location:user_login.php');
  exit;
}

?><!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Wildlife Conservancy System</title>
  <style>
    /* Global Styles */
    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      margin: 0;
      padding: 0;
      background-color: #f5f6f5; /* Light grey-green background */
    }

    h1, h2, h3 {
      color: #1a3c34; /* Dark green for headings */
    }

    a {
      text-decoration: none;
      color: inherit;
    }

    .container {
      width: 90%;
      max-width: 1200px;
      margin: 0 auto;
    }

    /* Navigation Bar */
    nav {
      background-color: #1a3c34; /* Dark green */
      color: white;
      padding: 1.2rem 0;
      position: fixed;
      width: 100%;
      top: 0;
      z-index: 1000;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    }

    nav .container {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    nav h1 {
      font-size: 1.8rem;
      font-weight: 600;
      color: #ffffff; /* White for visibility */
      margin: 0;
      letter-spacing: 1px;
    }

    nav ul {
      list-style: none;
      display: flex;
      gap: 2rem;
      margin: 0;
    }

    nav ul li a {
      color: #e0f2e9; /* Light green for links */
      font-weight: 500;
      font-size: 1.1rem;
      transition: color 0.3s ease;
    }

    nav ul li a:hover {
      color: #76c893; /* Brighter green on hover */
    }

    /* Hero Section */
    .hero {
      background-image: url('https://images.unsplash.com/photo-1547471080-7cc2caa01a7e?ixlib=rb-4.0.3&auto=format&fit=crop&w=1350&q=80');
      background-size: cover;
      background-position: center;
      height: 450px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      text-align: center;
      position: relative;
    }

    .hero::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(26, 60, 52, 0.6); /* Dark green overlay */
    }

    .hero-content {
      position: relative;
      z-index: 1;
    }

    .hero h2 {
      font-size: 3rem;
      margin-bottom: 1.5rem;
      font-weight: 700;
      text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    }

    .hero p {
      font-size: 1.3rem;
      font-weight: 300;
      text-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
    }

    /* Sections */
    section {
      padding: 5rem 0;
    }

    section h2 {
      text-align: center;
      margin-bottom: 3rem;
      font-size: 2.2rem;
      font-weight: 600;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 2rem;
    }

    /* Updated Dashboard Section Styling */
    #dashboard .card {
      background-color: white;
      padding: 2rem;
      border-radius: 15px;
      box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
      text-align: left;
      position: relative;
      transition: transform 0.2s;
    }

    #dashboard .card:hover {
      transform: translateY(-5px);
    }

    #dashboard .card::before {
      content: '';
      display: block;
      width: 40px;
      height: 40px;
      background-size: cover;
      margin-bottom: 1rem;
    }

    #dashboard .card:nth-child(1)::before {
      background-image: url('https://img.icons8.com/ios-filled/50/27ae60/camera.png');
    }

    #dashboard .card:nth-child(2)::before {
      background-image: url('https://img.icons8.com/ios-filled/50/27ae60/shield.png');
    }

    #dashboard .card:nth-child(3)::before {
      background-image: url('https://img.icons8.com/ios-filled/50/27ae60/line-chart.png');
    }

    #dashboard .card:nth-child(4)::before {
      background-image: url('https://img.icons8.com/ios-filled/50/27ae60/group.png');
    }

    #dashboard .card h3 {
      margin: 0.5rem 0;
      font-size: 1.2rem;
      font-weight: bold;
      color: #1a3c34;
    }

    #dashboard .card p {
      color: #666;
      font-size: 0.9rem;
      line-height: 1.4;
    } 

    @media (min-width: 768px) {
      #dashboard .grid {
        grid-template-columns: repeat(2, 1fr);
      }
    } 

    /* Analytics and Community Sections */
    .card {
      background-color: white;
      padding: 2rem;
      border-radius: 12px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
      transition: transform 0.3s ease, box-shadow 0.3s ease;
    } 

    .card:hover {
      transform: translateY(-5px);
      box-shadow: 0 6px 16px rgba(0, 0, 0, 0.12);
    }

    .card h3 {
      margin-bottom: 1rem;
      color: #27ae60; /* Medium green for card headings */
      font-weight: 600;
    } 

    .card p {
      color: #4a4a4a;
      font-size: 0.95rem;
      line-height: 1.5;
    } 

    /* Community Section */
    .community {
      text-align: center;
    } 

    .community button {
      background-color: #27ae60; /* Medium green */
      color: white;
      border: none;
      padding: 0.8rem 2rem;
      border-radius: 6px;
      cursor: pointer;
      margin-top: 1.5rem;
      font-size: 1rem;
      transition: background-color 0.3s ease;
    }

    .community button:hover {
      background-color: #219a52; /* Slightly darker green */
    }

    /* Footer */
    footer {
      background-color: #1a3c34; /* Dark green */
      color: #e0f2e9; /* Light green */
      text-align: center;
      padding: 1.5rem 0;
      font-size: 0.9rem;
    }

    /* Chart container */
    .chart-container {
      overflow-x: auto;
    }
  </style>
</head>

<body>
  <nav>
    <div class="container">
      <h1>AI Wildlife Conservancy</h1>
      <ul>
        <li><a href="#dashboard">Dashboard</a></li>
        <li><a href="#alerts">Alerts</a></li>
        <li><a href="#analytics">Analytics</a></li>
        <li><a href="#community">Community</a></li>
        <button onclick="logout()">Logout</button>

      </ul>
    </div>
  </nav>

  <section class="hero">
    <div class="hero-content">
      <h2>Protecting Wildlife with AI</h2>
      <p>Real-time monitoring, threat detection, and data-driven insights to preserve biodiversity.</p>
    </div>
  </section>

  <section id="dashboard">
    <div class="container">
      <h2>Real-Time Monitoring</h2>
      <div class="grid">
        <div class="card">
          <h3>Real-Time Monitoring</h3>
          <p>AI-enabled cameras and drones provide continuous surveillance across vast habitats.</p>
        </div>
        <div class="card">
          <h3>Threat Prevention</h3>
          <p>Automated detection of poachers and intrusions for rapid response and security.</p>
        </div>
        <div class="card">
          <h3>Data Analytics</h3>
          <p>Predictive models analyze wildlife behavior and habitat changes effectively.</p>
        </div>
        <div class="card">
          <h3>Community Engagement</h3>
          <p>Interactive apps empower local communities to report and collaborate.</p>
        </div>
      </div>
    </div>
  </section>
  <section id="alerts" style="background-color: #f5f6f5;">

    <div class="container">
  
      <h2>Threat Alerts</h2>
  
      <div class="alert">
  
        <div>
          <h3>Poaching Alert</h3>
          <p id="threatText">Suspicious activity detected in Sector 4 at 14:35.</p>
        </div>
  
        <div class="camera-feed-container">
          <h2>Live Surveillance Camera Feed</h2>
          <div id="cameraFeed">
            <img src="https://i.pinimg.com/474x/54/47/0c/54470c87775bbaf721c4ea9bb6666217.jpg" 
     alt="Camera Feed Mock" id="cameraFrame">

          </div>
  
          <button id="refreshFeed">Refresh Feed</button>
        </div>
        
         
  
        <button id="dispatchRangers">Dispatch Rangers</button>

  
      </div>
  
    </div>
  
  </section>
  
  

  <section id="analytics">
    <div class="container">
      <h2>Data Analytics</h2>
      <div class="grid">
        <div class="card">
          <h3>Wildlife Behavior Trends</h3>
          <p>AI-driven insights into migration patterns and population dynamics.</p>
        </div>
        <div class="card">
          <h3>Habitat Health</h3>
          <p>Predictive models forecast environmental risks and habitat changes.</p>
        </div>
      </div>

      <div class="grid">
        <div class="card chart-container">
          <h3>Population Trends</h3>
          <canvas id="populationChart" width="400" height="200"></canvas>
        </div>
        <div class="card chart-container">
          <h3>Threat Alerts</h3>
          <canvas id="alertsChart" width="400" height="200"></canvas>
        </div>
      </div>
    </div>
  </section>

  <section id="community" style="background-color: #f5f6f5;">
    <div class="container community">
      <h2>Community Engagement</h2>
      <p>Local communities can report suspicious activities via our Chat Bot.</p>
      <button id="talkToUsBtn">Talk to Us</button>
      
<!-- Chatbot Widget -->
<div id="chatbotWidget" style="display: none;">
  <div id="chatbotMessages"></div>
  
  <!-- User Input -->
  <input type="text" id="chatbotInput" placeholder="Ask me anything...">
  
  <!-- Send Message Button -->
  <button id="sendMessage">Send</button>

  <!-- Close Button -->
  <button id="closeChatbox">X</button>
</div>
    </div>
  </section>

  <footer>
    <p>&copy; 2025 AI Wildlife Conservancy. All rights reserved.</p>
  </footer>

  

  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    //  population trend chart
    var ctx1 = document.getElementById('populationChart').getContext('2d');
    var populationChart = new Chart(ctx1, {
      type: 'line',
      data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
        datasets: [{
          label: 'Animal Population',
          data: [1200, 1150, 1100, 1050, 1000, 950, 900],
          borderColor: 'rgba(39, 174, 96, 1)',
          fill: false
        }]
      }
    });

    // threat alert chart
    var ctx2 = document.getElementById('alertsChart').getContext('2d');
    var alertsChart = new Chart(ctx2, {
      type: 'bar',
      data: {
        labels: ['Poaching', 'Trespassing', 'Habitat Destruction'],
        datasets: [{
          label: 'Alert Frequency',
          data: [8, 3, 5],
          backgroundColor: 'rgba(231, 76, 60, 0.8)',
        }]
      }
    });
  </script>
    <script>
    function logout() {
      fetch('logout.php', { method: 'POST', credentials: 'include' })
        .then(() => window.location.href = 'user_login.php');
    }
  </script>
   <script>
    // Check if the user is logged in
    if (localStorage.getItem('isLoggedIn') !== 'true') {
      // If not logged in, redirect to login page
    }

    // Logout function to clear login status and redirect to login page
    function logout() {
      localStorage.setItem('isLoggedIn', 'false');
      window.location.href = 'user_login.php'; // Redirect to login page
    }
  </script>
  <script>
    const images = [
      "https://i.pinimg.com/474x/54/47/0c/54470c87775bbaf721c4ea9bb6666217.jpg",
      "https://i.pinimg.com/474x/a9/7c/30/a97c30e95d85c486b94c77c0d20f39a7.jpg",
      "https://i.pinimg.com/474x/fc/b9/ab/fcb9abffaf8f51a1442b6d87aa1db8d1.jpg",
      "https://i.pinimg.com/474x/8e/61/77/8e617739d38d11b0646ec9e3b8596d4d.jpg"
    ];
  
    const messages = [
      "Unidentified movement detected in Sector 4.",
      "Thermal anomaly spotted near waterhole.",
      "Large animal detected moving rapidly.",
      "Poacher footprints found during patrol.",
      "Drone detected flying over restricted zone."
    ];
  
    document.getElementById("refreshFeed").addEventListener("click", function() {
      // Pick random image and message
      const randomImage = images[Math.floor(Math.random() * images.length)];
      const randomMessage = messages[Math.floor(Math.random() * messages.length)];
  
      // Update the camera image
      document.getElementById("cameraFrame").src = randomImage;
  
      // Update the threat text
      document.getElementById("threatText").textContent = randomMessage;
    });
  </script>
  <script>
    document.getElementById('dispatchRangers').addEventListener('click', function () {
      showNotification('🚓 Dispatch Alert: Rangers have been dispatched to Sector 4!');
    });
  
    function showNotification(message) {
      const notification = document.createElement('div');
      notification.className = "bg-green-500 text-white px-6 py-4 rounded-lg shadow-lg mb-4 animate-slide-in";
      notification.innerText = message;
  
      const container = document.getElementById('notification-container');
      container.appendChild(notification);
  
      // Remove after 4 seconds
      setTimeout(() => {
        notification.classList.add('opacity-0', 'transition-opacity', 'duration-500');
        setTimeout(() => {
          notification.remove();
        }, 500);
      }, 4000);
    }
  </script>
  <!-- Notification -->
<div id="notification-container" style="position: fixed; top: 20px; right: 20px; z-index: 9999;"></div>
<script>
  document.getElementById('dispatchRangers').addEventListener('click', function () {
    showNotification('🚓 Rangers are on their way to Sector 4!');
  });

  function showNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.innerText = message;

    document.getElementById('notification-container').appendChild(notification);

    // Auto-remove after 4 seconds
    setTimeout(() => {
      notification.style.opacity = '0';
      setTimeout(() => {
        notification.remove();
      }, 500);
    }, 4000);
  }
</script>
<style>
  .notification {
    background-color: #28a745;
    color: white;
    padding: 16px 24px;
    margin-bottom: 10px;
    border-radius: 8px;
    box-shadow: 0px 4px 12px rgba(0, 0, 0, 0.2);
    font-size: 16px;
    transition: opacity 0.5s ease;
    animation: slideIn 0.5s ease forwards;
  }
  
  /* Slide In Animation */
  @keyframes slideIn {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
  </style>
  

  
  
  
  
   
  </script>
  <script src="signup.js"></script>

  <script src="chatbot.js"></script>
  <link rel="stylesheet" href="chatbot.css">
  <link rel="stylesheet" href="camera-feed.css">
  <script src="camera-feed.js"></script>
  <script src="./notifications.js"></script>
  <link rel="stylesheet" href="notifications.css">

</body>

</html>
