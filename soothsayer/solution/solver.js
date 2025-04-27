Java.perform(function() {
    const MainActivity = Java.use("com.bsidessf.soothsayer.MainActivity");
    var choices = []; // Array to store calculated choices
    try {
        const Response = Java.use("okhttp3.Response");
        Response.body.implementation = function() {
            var responseBody = this.body();
            if (responseBody !== null) {
                var content = responseBody.string();
                console.log("[+] Flag response body: " + content);

                return Java.use("okhttp3.ResponseBody").create.overload(
                    'okhttp3.MediaType', 'java.lang.String'
                ).call(
                    Java.use("okhttp3.ResponseBody"),
                    responseBody.contentType(),
                    content
                );
            } else {
                console.log("[-] Response body is null");
                return null;
            }
        };
        console.log("[+] Hooked okhttp3.Response.body().string()");
    } catch (err) {
        console.log("[-] Error hooking Response.body().string(): " + err);
    }
    // Save a reference to the MainActivity instance for later use
    MainActivity.computeChoice.implementation = function(choice) {
        const mt = this.mt.value;
        const nextDouble = mt.nextDouble();
        const num = Math.floor((nextDouble * 1000) + 15) % 2;
        // All guesses are right
        const User = Java.use("com.bsidessf.soothsayer.User");
        const user = User.getInstance();
        user.score.value = user.score.value + 1;
        choices.push(num);
        return;
    };
    MainActivity.resetGame.implementation = function() {
        choices = [];
        console.log("[+] Calling computeChoice 30 times")
        for (let i = 0; i < 30; i++) {
            const choice = i % 2; // alternate 0 and 1
            const activity = this;
            activity.computeChoice(choice);
        }
        console.log(choices);
        console.log("[+] Called computeChoice 30 times");
        for (let i = 0; i < 30; i++) {
            const predictedChoice = choices[i];
            const activity = this;
            activity.sendGuess(predictedChoice);
            console.log(`[>] sendGuess(${predictedChoice})`);
        }
    }
});