<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dragon Detector</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
<?php
  $ip = $_REQUEST['ip'];

  if (str_contains($ip, "\"")) {
      echo "<h1>🛑 Invalid IP Address!</h1>";
      echo "<p>That doesn't look like a valid IP address. Are you sure that's not a goblin lair?</p>";
      echo '<a href="/">Try again</a>';
      exit;
  }


  echo "<h1>";
  system("bash /app/dragon-detector-ai \"$ip\"");
  echo "</h1>";

  echo '<br><a href="/">Check another IP</a>';
?>
    </div>
</body>
</html>
