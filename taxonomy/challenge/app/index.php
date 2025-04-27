<?php
// index.php
$db = new SQLite3('/data/dragons.db');

// Search functionality
$search = $_GET['search'] ?? '';

if($search == '') {
  $sql = "SELECT * FROM dragons WHERE is_classified = 0";
  $result = $db->query($sql);
} else {
  $sql = "SELECT * FROM dragons WHERE (name LIKE '%$search%' OR color LIKE '%$search%' OR size LIKE '%$search%' OR habitat LIKE '%$search%') AND is_classified = 0";
}

$result = $db->query($sql);

if(!$result) {
  echo "<div class='error'>An error occurred while accessing the database. Please try again later.</div>";
  echo "<div class='error'>Your query:</div>";
  echo "<pre><tt>$sql</tt></pre>";
  echo "<div><a href='/'>Back</a></div>";
  exit(0);
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Dragon Taxonomy</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <h1>Dragon Taxonomy</h1>

        <form method="get" class="mb-4">
            <div class="input-group">
                <input type="text" name="search" class="form-control" 
                       placeholder="Search dragons..." value="<?= htmlspecialchars($search) ?>">
                <button type="submit" class="btn btn-primary">Search</button>
            </div>
        </form>

        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Color</th>
                    <th>Size</th>
                    <th>Habitat</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($row = $result->fetchArray(SQLITE3_ASSOC)): ?>
                <tr>
                    <td><?= htmlspecialchars($row['name']) ?></td>
                    <td><?= htmlspecialchars($row['color']) ?></td>
                    <td><?= htmlspecialchars($row['size']) ?></td>
                    <td><?= htmlspecialchars($row['habitat']) ?></td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
