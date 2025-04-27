<!DOCTYPE html>
<?php
  error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);
?>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dragon Evidence</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Dragon Evidence</h1>

<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['dragon_file'])) {
        $file = $_FILES['dragon_file']['tmp_name'];
        
        // We demand FREEDOM (from secure defaults)
        libxml_disable_entity_loader(false);
        $dom = new DOMDocument();
        $dom->loadXML(file_get_contents($file), LIBXML_NOENT | LIBXML_DTDLOAD);
        
        echo "<h2>Dragon Evidence Found:</h2>";
        echo "<pre>" . htmlspecialchars($dom->saveXML()) . "</pre>";
    }
} else {
?>
        <p>They said dragons were myths... but we know better.</p>
        <p class="fire">Upload your classified XML evidence to expose the truth.</p>

        <form class="dragons" method="POST" enctype="multipart/form-data">
            <input type="file" name="dragon_file" accept=".xml">
            <input type="submit" value="Submit Evidence">
        </form>
<?php
}
?>

        <footer>
            <p>🔥 The truth is out there... 🔥</p>
        </footer>
    </div>
</body>
</html>
