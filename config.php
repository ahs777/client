<?php
require('./vendor/autoload.php');

# Add your client ID and Secret
$client_id = "193191279862-bfou4k9nmengrq0qut46i7a8jmdpi9ol.apps.googleusercontent.com";
$client_secret = "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";

$client = new Google\Client();
$client->setClientId($client_id);
$client->setClientSecret($client_secret);

# redirection location is the path to login.php
$redirect_uri = 'http://localhost/client/login.php';
$client->setRedirectUri($redirect_uri);
$client->addScope("email");
$client->addScope("profile");
