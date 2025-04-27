
## Firebase - setup notes 
* On Firebase Console - choose authentication 
* Enable Anonymous provider 
* On Firebase Console - choose Firestore Database
* Start a collection - `users`
* Update the `Rules` to allow the app to talk to it
```
rules_version = '2';

service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{uid} {
      allow create: if request.auth != null;
      allow read, update, delete: if request.auth != null && request.auth.uid == uid;
    }
  }
}
```

## App  - notes 
* Select `Add app` on console
* Choose `Android`
* Enter `Android package name` as `com.example.soothsayer`
* Enter `App nickname` as `Soothsayer`
* Click `Register App`
* Download the config file - `google-services.json`
* In Android Studio, add it to the `app` directory
* In Android Studio, `Build > Build App Bundle(s) / APK (s) > Build APK`
* From the project directory `app > build > outputs > apk > debug` copy app-debug.apk 
* Rename it to `soothsayer.apk`
* Move it to `distfiles`


## Server - deployment notes 
* Export key for server as `soothsayer-firebase.json`
* Upload the key to the server 

