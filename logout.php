<?php
// Initialize the session
session_start();
 // google logout start
 if(!isset($_SESSION['token'])){
    header('Location: login.php');
    exit;
  }
  
  require('./config.php');
  $client = new Google\Client();
  $client->setAccessToken($_SESSION['token']);
  # Revoking the google access token
  $client->revokeToken();
  
  # Deleting the session that we stored
  $_SESSION = array();
  
  if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
  }
  //goolge logout end
  
// Unset all of the session variables
$_SESSION = array();
 
// Destroy the session.
session_destroy();
 
// Redirect to login page
header("location: login.php");
exit;
?>