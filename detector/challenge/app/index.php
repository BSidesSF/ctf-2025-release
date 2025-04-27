<script>
function validateIP() {
    const ipFormat = /^^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$$/;
    const ip = document.getElementById('dragon-ip').value;
    
    if(!ip.match(ipFormat)) {
        alert('That IP smells of goblins! Try a real address!');
        return false;
    }
    document.getElementById('dragon-form').submit();
    return true;
}
</script>

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
    <h1>🛡️ Dragon Detector 🐉</h1>
    <p class="subtitle">Enter an IP address to see if a dragon lives there!</p>
    <p>This uses state of the art copyrighted AI, and it's worth A LOT of money!!</p>
    <form id="dragon-form" action="detect-dragon.php" method="post" onsubmit="return validateIP();">
      <input type="text" id="dragon-ip" name="ip" placeholder="Enter IP address..." required>
      <button type="submit">Detect Dragon</button>
    </form>
    <div class="dragon-image">
      <img src="dragon.gif" alt="A friendly dragon">
    </div>
  </div>
</body>
</html>
