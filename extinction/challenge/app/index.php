<?php
$correct_username = 'admin';
$correct_password = 'admin';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $encoded_creds = $_REQUEST['encoded_creds'] ?? '';

    if(str_contains($encoded_creds, 'YWRtaW46YWRtaW4')) {
      $error_message = "AHA! We are aware that that password has been leaked! CAUGHT YOU!!";
    } else {
      $decoded_creds = base64_decode($encoded_creds);
      $creds_parts = explode(':', $decoded_creds);

      if (count($creds_parts) !== 2) {
        $error_message = '⚠️ Invalid authentication runes! Dragon peril persists...';
      } else {
        $username = $creds_parts[0];
        $password = $creds_parts[1];

        if ($username === $correct_username && $password == $correct_password) {
          $flag = file_get_contents("/flag.txt");
          $success_message = "Congratulations! Your flag is <tt>$flag</tt>";
        } else {
          $error_message = '⚡ Authentication failed! Dragon extinction counter: ░░░░░░░░░░] 90%';
        }
      }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dragon Preservation System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: #0a2e36 url('dragon-scale-pattern.png');
            color: #c9d1d3;
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        .dragon-auth-box {
            background: rgba(12, 45, 52, 0.9);
            border: 2px solid #1c6e72;
            border-radius: 15px;
            box-shadow: 0 0 20px #1c6e72;
        }
        .btn-dragon {
            background: #1c6e72;
            color: #fff;
            transition: all 0.3s;
        }
        .btn-dragon:hover {
            background: #13494d;
            transform: scale(1.05);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-4">
                <div class="dragon-auth-box p-4">
                    <h2 class="text-center mb-4">🐉 Dragon Preservation System 🛡️</h2>

                    <?php if (isset($error_message)): ?>
                        <div class="alert alert-danger"><?= $error_message ?></div>
                    <?php elseif (isset($success_message)): ?>
                        <div class="alert alert-success"><?= $success_message ?></div>
                    <?php endif; ?>


        <p>An extinction weapon has been activated against the dragons, and only YOU can stop it!</p>

        <p>Our intelligence reports that the Ally Name is <strong><tt>admin</tt></strong> and the key is <strong><tt>admin</tt></strong>, but that's not working! Can you find a way to use that account??</p>

        <form method="POST" onsubmit="return encodeDragonRunes(event)">
            <div class="mb-3">
                <label for="username" class="form-label">Dragon Ally Name</label>
                <input type="text" class="form-control" id="username" required>
            </div>
            <div class="mb-4">
                <label for="password" class="form-label">Ancient Rune Key</label>
                <input type="password" class="form-control" id="password" required>
            </div>
            <input type="hidden" name="encoded_creds" id="encoded_creds">
            <button type="submit" class="btn btn-dragon w-100">Activate Preservation Runes</button>
        </form>

        <script>
            function encodeDragonRunes(event) {
                event.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const combined = `${username}:${password}`;
                document.getElementById('encoded_creds').value = btoa(combined);
                document.getElementById('username').value = '';
                document.getElementById('password').value = '';
                event.target.submit();
            }
        </script>
                </div>
            </div>
        </div>
    </div>
</body>
</body>
</html>
