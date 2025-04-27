<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dragon Investment Portal</title>
    <!-- Link to external CSS file -->
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h1>Dragon Investment Portfolio Assessment</h1>

        <!-- Dropdown menu for hoard type -->
        <label for="hoardType">Select Hoard Type:</label>
        <select id="hoardType" name="hoardType">
            <option value="gold">Gold Hoard</option>
            <option value="gemstone">Gemstone Cache</option>
            <option value="artifact">Artifact Collection</option>
        </select>

        <!-- Form for hoard details -->
        <form id="investmentForm">
            <label for="gold">Gold (in kg):</label>
            <input type="number" id="gold" name="gold" required>

            <label for="gems">Gems (count):</label>
            <input type="number" id="gems" name="gems" required>

            <label for="artifacts">Artifacts (count):</label>
            <input type="number" id="artifacts" name="artifacts" required>

            <button type="button" onclick="submitForm()">Valuate Hoard</button>
        </form>

        <!-- Output field to display the final hoard -->
        <h2>Final Hoard Valuation:</h2>
        <output id="hoardOutput"></output>
    </div>

    <script>
        function submitForm() {
            const formData = {
                hoardType: document.getElementById('hoardType').value,
                gold: document.getElementById('gold').value,
                gems: document.getElementById('gems').value,
                artifacts: document.getElementById('artifacts').value
            };

            const xhr = new XMLHttpRequest();
            xhr.open('POST', 'backend.php', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.onload = function() {
                if (xhr.status === 200) {
                    try {
                        const response = JSON.parse(xhr.responseText);
                        if (response.status === "success") {
                            document.getElementById('hoardOutput').innerHTML = response.message;
                        } else {
                            document.getElementById('hoardOutput').textContent = "Error valuating hoard.";
                        }
                    } catch (e) {
                        document.getElementById('hoardOutput').textContent = "Invalid server response.";
                    }
                } else {
                    document.getElementById('hoardOutput').textContent = "Failed to connect to server.";
                }
            };
            xhr.send(JSON.stringify(formData));
        }
    </script>
</body>
</html>
