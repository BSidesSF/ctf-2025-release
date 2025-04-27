const puppeteer = require('puppeteer');
const path = require('path');

const express = require('express');
const app = express();
const port = 3003;

app.use(express.urlencoded({ extended: true })); // for form-encoded data

function wait(seconds) {
    return new Promise(resolve => setTimeout(resolve, seconds * 1000));
}

async function visit(url) {
    const page = await browser.newPage();
    await page.goto(url);
    await wait(10);
    await page.close();
}

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Visa Submission Form for Glorious Arstotzka!</title>
</head>
<body>
  <h1>Visa Submission</h1>
  <form action="/submit-url" method="POST">
    <label for="url">Visa URL for Agent Review:</label>
    <input type="text" id="url" name="url" required>
    <button type="submit">Submit</button>
  </form>
</body>
</html>
    `);
});

app.post('/submit-url', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).send('Missing "url" in request body');
    }

    if (!(url.startsWith('https://') || url.startsWith('http://'))) {
        return res.status(400).send('Bad URL comrade, try something http:// or https://');
    }

    // Do something with the URL (for now, just log it)
    console.log(`[STATUS] Visiting submitted URL: ${url}`);
    visit(url);

    res.status(200).send('URL received comrade');
});

let browser = null;

(async () => {
    browser = await puppeteer.launch({
        headless: false, // Extensions require non-headless mode
        executablePath: process.env.PUPPETEER_EXEC_PATH,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            `--disable-extensions-except=${path.resolve(__dirname, 'extension')}`,
            `--load-extension=${path.resolve(__dirname, 'extension')}`,
        ]
    });

    app.listen(port, '0.0.0.0', () => {
        console.log(`Server listening at :${port}`);
    });
})();
