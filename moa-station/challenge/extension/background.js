chrome.browserAction.onClicked.addListener((tab) => {
    console.log(`Disappointing.`);
});

// Use of restricted keywords result in M.O.A. citation
const RESTRICTED_MESSAGES = [
    'jorji',
    'ezic',
    'food',
    'mercy',
];

let recorded_keystrokes = ``;

const MOA_AUTHENTICATION_SECRET_FLAG = `CTF{TRUST_BUT_VER1FY}`;
localStorage.setItem('secret', MOA_AUTHENTICATION_SECRET_FLAG);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Store comrad keystrokes
    if (request.action === "keystroke") {
        recorded_keystrokes = recorded_keystrokes + request.payload;
        sendResponse({});
    }

    // Inspect keystrokes for contraband
    const violations = RESTRICTED_MESSAGES.map(message => {
        const regex = new RegExp(message, 'g');
        const match = regex.exec(recorded_keystrokes);
        if(!match) {
            return false;
        }
        let offending_index = match.index;
        // show comrad the context for crime
        const context_size = 1000;
        const offensive_text = recorded_keystrokes.slice(offending_index - context_size, offending_index + context_size);
        return offensive_text.replace(message, `<span class="highlight">${message}</span>`);
    }).filter(offense => offense !== false);

    // alert comrad of crimes
    if(violations.length > 0) {
        recorded_keystrokes = ``;
        violations.map(violation => {
            window.open(`alert.html?offensive_text=` + encodeURIComponent(violation));
        })
    }

    return true;
});