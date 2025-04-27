package com.bsidessf.soothsayer;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;

// Firebase related
import com.bsidessf.soothsayer.User;
import com.google.firebase.auth.AuthResult;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.GetTokenResult;
import com.google.firebase.firestore.FirebaseFirestore;


// For Mersenne Twister
import org.apache.commons.math3.random.MersenneTwister;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;

// For making request
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;



public class MainActivity extends AppCompatActivity {
    private FirebaseAuth mAuth;
    private FirebaseFirestore mDB;
    private static String dbPath = "users";
    private MersenneTwister mt;
    final OkHttpClient client = new OkHttpClient().newBuilder()
            .connectTimeout(2, TimeUnit.MINUTES)
            .readTimeout(2, TimeUnit.MINUTES)
            .writeTimeout(2, TimeUnit.MINUTES)
            .build();
    private String responseStr = null;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Instantiate Firebase Auth
        mAuth = FirebaseAuth.getInstance();
        //Instantiate Firebase Firestore DB
        mDB = FirebaseFirestore.getInstance();
        initializeUser();
        // Populate the Activity
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
        // Spin the disk
        ImageView image = findViewById(R.id.disc_image);
        image.animate().rotation(180f).setDuration(10000).start();

        // All the UI elements needed
        RadioGroup radioGroup = (RadioGroup) findViewById(R.id.radio_group);
        Button guessButton = findViewById(R.id.guess_button);
        TextView score = findViewById(R.id.score_value);
        TextView round = findViewById(R.id.round_value);
        Button flagButton = findViewById(R.id.flag_button);
        Button resetButton = findViewById(R.id.reset_button);

        // On clicking Guess button, check guess
        // Increment score, update round
        guessButton.setOnClickListener(new View.OnClickListener(){
            public void onClick(View v) {
                int choice = 1;
                int selectedId = radioGroup.getCheckedRadioButtonId();
                if(selectedId == R.id.egg_radio){
                    choice = 0;
                }
                sendGuess(choice);
                User user = User.getInstance();
                int roundsLeft = 30 - user.guess.size();
                round.setText(String.valueOf(roundsLeft));
                score.setText(String.valueOf(user.score));
            }
        });

        // Fetch the flag from the server if user completed atleast 30 rounds
        flagButton.setOnClickListener(new View.OnClickListener(){
            public void onClick(View v) {
                User user = User.getInstance();
                if(user.guess.size() >= 30){
                    getidToken();
                }
                else{
                    Toast.makeText(MainActivity.this, "Need to have atleast 30 guesses for flag.",
                            Toast.LENGTH_SHORT).show();
                }
            }
        });
        // Reset the user
        resetButton.setOnClickListener(new View.OnClickListener(){
            public void onClick(View v) {
              resetGame();
              score.setText("0");
              round.setText("30");
            }
        });
    }
    // Get user, reinitiliaze seed, mersenne twister
    private User reinit(String uid){
        User user = User.getInstance();
        user.reinitialize(uid);
        mt = new MersenneTwister(user.seed);
        //Log.d("New Seed:",String.valueOf(user.seed));
        return user;
    }
    private void initializeUser() {
        FirebaseUser currentUser = mAuth.getCurrentUser();
        if(currentUser == null){
            mAuth.signInAnonymously()
                    .addOnCompleteListener(this, new OnCompleteListener<AuthResult>() {
                        @Override
                        public void onComplete(@NonNull Task<AuthResult> task) {
                            if (task.isSuccessful()) {
                                // Sign in success, update UI with the signed-in user's information
                                Log.d("Firebase:", "signInAnonymously:success");
                                FirebaseUser currentUser = mAuth.getCurrentUser();
                                Log.d("Firebase:","currentuser" + currentUser);
                                String uid = mAuth.getCurrentUser().getUid();
                                User user = reinit(uid);
                                mDB.collection(dbPath).document(uid)
                                        .set(user)
                                        .addOnSuccessListener(new OnSuccessListener<Void>() {
                                            @Override
                                            public void onSuccess(Void aVoid) {
                                                Log.d("Writing user to DB:", "success");
                                            }
                                        })
                                        .addOnFailureListener(new OnFailureListener() {
                                            @Override
                                            public void onFailure(@NonNull Exception e) {
                                                Log.w("Writing user to DB:", "error", e);
                                            }
                                        });
                            } else {
                                // If sign in fails, display a message to the user.
                                Log.w("Firebase:", "signInAnonymously:failure", task.getException());
                                Toast.makeText(MainActivity.this, "Authentication failed.",
                                        Toast.LENGTH_SHORT).show();
                            }
                        }
                    });
        }
        else{
            String uid = mAuth.getCurrentUser().getUid();
            User user = reinit(uid);
            mDB.collection(dbPath).document(uid)
                    .set(user)
                    .addOnSuccessListener(new OnSuccessListener<Void>() {
                        @Override
                        public void onSuccess(Void aVoid) {
                            Log.d("Writing user to DB:", "success");
                        }
                    })
                    .addOnFailureListener(new OnFailureListener() {
                        @Override
                        public void onFailure(@NonNull Exception e) {
                            Log.w("Writing user to DB:", "error", e);
                        }
                    });
        }
    }
    // Reset the game
    private void resetGame(){
        String uid = mAuth.getCurrentUser().getUid();
        if(uid == null){
            Activity activity = MainActivity.this;
            activity.runOnUiThread(new Runnable() {
                public void run() {
                    Toast.makeText(activity, "Invalid state, restart app.", Toast.LENGTH_SHORT).show();
                }
            });
            return;
        }
        // New seed and new guess array
        User user = reinit(uid);
        mDB.collection(dbPath).document(user.id)
                .set(user)
                .addOnSuccessListener(new OnSuccessListener<Void>() {
                    @Override
                    public void onSuccess(Void aVoid) {
                        Log.d("Writing new game to DB:", "success");
                    }
                })
                .addOnFailureListener(new OnFailureListener() {
                    @Override
                    public void onFailure(@NonNull Exception e) {
                        Log.w("Writing new game to DB:", "error", e);
                    }
                });
    }
    // Send the guesses to the server
    private void sendGuess(int choice){
        User user = User.getInstance();
        user.guess.add(choice);
        computeChoice(choice);
        List<Integer> guess = user.guess;
        Integer[] simpleArray = new Integer[guess.size()];
        guess.toArray(simpleArray);
        mDB.collection(dbPath).document(user.id)
                .set(user)
                .addOnSuccessListener(new OnSuccessListener<Void>() {
                    @Override
                    public void onSuccess(Void aVoid) {
                        Log.d("Writing guess to DB:", "success");
                    }
                })
                .addOnFailureListener(new OnFailureListener() {
                    @Override
                    public void onFailure(@NonNull Exception e) {
                        Log.w("Writing guess to DB:", "error", e);
                    }
                });
    }

    // Takes the seed to generate a number using Mersenne Twister
    // Does a bunch of operations and determines the right choice
    protected void computeChoice(int choice){
        double number = mt.nextDouble();
        number = number * 1000;
        number = number + 15;
        int num = 0;
        num = (int) Math.floor(number);
        num = num % 2;
        // 0 is egg, 1 is dragon
        if(choice == num){
            User user = User.getInstance();
            user.score = user.score + 1;
        }
    }

    // Getting the flag
    private void getFlag(String token){
        String BASE_URL = "https://soothsayer-50ffa0e6.challenges.bsidessf.net/";
        //String BASE_URL = "http://10.0.0.176:8000";
        RequestBody formBody = new FormBody.Builder()
                .add("token", token)
                .build();
        Request request = new Request.Builder()
                .url(BASE_URL + "/get-flag")
                .post(formBody)
                .build();
            client.newCall(request).enqueue(new Callback() {

                @Override
                public void onFailure(@NotNull Call call, @NotNull IOException e) {
                    e.printStackTrace();
                }

                @Override
                public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
                    if (response.isSuccessful()) {
                        responseStr = "Flag:" + response.body().string();
                        Log.d("Response:",responseStr);
                        if (response.code() != 200){
                            responseStr = "Error fetching flag";
                        }
                        Activity activity = MainActivity.this;
                        activity.runOnUiThread(new Runnable() {
                            public void run() {
                                Toast.makeText(activity, responseStr, Toast.LENGTH_SHORT).show();
                            }
                        });
                        Log.d("Response:", responseStr);
                    }
                }

    });
    }
    // Creating the Idtoken to talk to the server
    private void getidToken(){
        FirebaseUser mUser = FirebaseAuth.getInstance().getCurrentUser();
        mUser.getIdToken(true)
                .addOnCompleteListener(new OnCompleteListener<GetTokenResult>() {
                    public void onComplete(@NonNull Task<GetTokenResult> task) {
                        if (task.isSuccessful()) {
                            String idToken = task.getResult().getToken();
                            Log.d("Token",idToken);
                            getFlag(idToken);
                        } else {
                            Log.w("Token Fetch","Failed");
                        }
                    }
                });
    }
}

