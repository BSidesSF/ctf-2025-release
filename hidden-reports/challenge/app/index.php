<?php
// app/public/index.php
session_start();

$error = null; // Initialize error variable

function is_authenticated() {
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'];
}

function verify_credentials($password) {
  $query = "SELECT count(*) FROM agents WHERE username = 'dragonwatch' and password = '" . $password . "'";
  try {
    $db = new PDO('sqlite:/data/secrets.db');
    $stmt = $db->prepare($query);
    $stmt->execute();
    $count = $stmt->fetchColumn();

    return $count > 0;
  } catch (PDOException $e) {
    echo "<div class='error'>An error occurred while accessing the database. Please try again later.</div>";
    echo "<div class='error'>Your query:</div>";
    echo "<pre><tt>$query</tt></pre>";
    echo "<div><a href='/'>Back</a></div>";
    exit(0);
  }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['logout'])) {
        session_destroy();
        header('Location: /');
        exit;
    }

    if (!empty($_POST['passphrase'])) {
        if (verify_credentials($_POST['passphrase'])) {
            $_SESSION['authenticated'] = true;
            header('Location: /');
            exit;
        }
        $error = "⚠️ Incorrect password. Access denied!"; // Set error message
    }
}

if (is_authenticated()) {
    display_classified_dossier();
} else {
    show_login_form($error); // Pass error to login form
}

function display_classified_dossier() {
    echo <<<HTML
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="style.css">
        <title>Top Secret Dragon Dossier</title>
    </head>
    <body>
        <div class="container">
            <div class="classified">
                <h2>🐉 TOP SECRET: DRAGON INCURSION IMMINENT 🐉</h2>
                <p><strong>Flag:</strong> <tt>CTF{select-or-one-equals-one}</tt></p>
                <p><strong>Codename:</strong> Operation Firestorm</p>
                <p><strong>Threat Level:</strong> Apocalyptic</p>
                <p><strong>ETA:</strong> 2025-04-15T18:00:00Z</p>
                <div class="details">
                    <p><strong>Primary Entry Point:</strong> Mount St. Helens Caldera</p>
                    <p><strong>Estimated Hostiles:</strong> 12 Ancient Wyrms + Support</p>
                    <p><strong>Recommended Countermeasures:</strong></p>
                    <div class="countermeasures">
                        <p>- Mobilize Dragon Slayer Division</p>
                        <p>- Activate Arcane Shield Grid</p>
                        <p>- Deploy Anti-Air Ballistae</p>
                    </div>
                </div>
                <form method="post">
                    <button type="submit" name="logout">Burn Document</button>
                </form>
            </div>
        </div>
    </body>
    </html>
HTML;
}

function show_login_form($error = null) {
    $errorMessage = $error ? "<div class='error'>$error</div>" : ""; // Display error if exists
    echo <<<HTML
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="style.css">
        <title>Secret Dragon Dossier Login</title>
    </head>
    <body>
        <div class="container">
            <div class="dossier">
                $errorMessage
                <h1>🔒 CLASSIFIED EYES ONLY</h1>
                <p>This portal grants access to the secret dragon dossier.</p>
                <p><strong>Please avoid using an apostrophe (<tt>'</tt>) in your password, it causes weird errors!</strong></p>
                <form method="post">
                    <input type="password" name="passphrase" placeholder="Enter Authorization Code" required>
                    <button type="submit">Authenticate</button>
                </form>
                <div class="warning">⚠️ Unauthorized access will be met with extreme prejudice.</div>
            </div>
        </div>
    </body>
    </html>
HTML;
}
