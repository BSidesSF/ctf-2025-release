<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dragon Sightings</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

    <?php if ($_SERVER['REQUEST_METHOD'] === 'POST'): ?>
        <div class="thank-you-message">
            <p>Thank you for submitting your dragon sighting! We'll share it with experts in the field and let you know if it's indeed a dragon!</p>
        </div>
    <?php endif; ?>

    <header>
        <h1>Dragon Sightings</h1>
    </header>
    <main>
        <section class="form-section">
            <h2>Submit a Dragon Sighting</h2>
            <form id="sighting-form" method="POST" enctype="multipart/form-data">
                <label for="location">Location:</label>
                <input type="text" id="location" name="location" required>

                <label for="description">Description:</label>
                <textarea id="description" name="description" required></textarea>

                <label for="image">Upload Image:</label>
                <input type="file" id="image" name="image" accept="image/*">

                <button type="submit">Submit Sighting</button>
            </form>
        </section>

        <section class="gallery-section">
            <h2>Past Dragon Sightings</h2>
            <div class="gallery">
                <div class="image-card">
                    <img src="picture.php?file=uploads/dragon1.jpg" alt="Dragon 1">
                    <p>Location: Mountains of Moria</p>
                </div>
                <div class="image-card">
                    <img src="picture.php?file=uploads/dragon2.jpg" alt="Dragon 2">
                    <p>Location: Forests of Lothlórien</p>
                </div>
                <div class="image-card">
                    <img src="picture.php?file=uploads/dragon3.jpg" alt="Dragon 3">
                    <p>Location: Plains of Rohan</p>
                </div>
                <!-- Add more images here -->
            </div>
        </section>
    </main>
</body>
</html>
