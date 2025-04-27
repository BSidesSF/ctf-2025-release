Run `solution.py <challenge-url>` to test if Firebase and server are working. 

Run `solution.py` to get the guesses you need for each round and then plug into Android App. 

If you would like to generate the guesses for the seed to validate the app, run `solution.py` and then supply the seed. 

If you would like to use the Frida hook to solve the challenge, 
* Setup an Android Virtual Device with the image `Android 13.0 ('Tiramisu') | arm64 with Google APIs`
* Install `soothsayer.apk` on it 
* `adb root` 
* `adb push frida-server /data/local/tmp/frida-server`
* `adb shell chmod 755 /data/local/tmp/frida-server`
* `adb shell /data/local/tmp/frida-server &`
* `frida -U -f com.bsidessf.soothsayer -l solver.js`
* On the app, click the "Reset" button and then "Get Flag" button 
* Flag will be printed in the console, the app might crash though :)
