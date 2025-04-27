package com.example.dragonnames

import android.widget.Button
import android.os.Bundle
import android.widget.ImageView
import androidx.activity.ComponentActivity
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.random.Random

class MainActivity : ComponentActivity() {
    fun rot13(input: String): String {
        return input.map { char ->
            when {
                char in 'a'..'m' -> char + 13
                char in 'n'..'z' -> char - 13
                char in 'A'..'M' -> char + 13
                char in 'N'..'Z' -> char - 13
                else -> char
            }
        }.joinToString("")

    }


    @OptIn(ExperimentalEncodingApi::class)
    fun createFlag(): String {
        val part1 = rot13("PGS")
        val b64 = Base64.Default.decode("dzNhaw==")
        val part2 = b64.decodeToString()
        val x = 10 % 2
        val part3 = "T$x"
        val part4 = resources.getString(R.string.part4)
        val y = if (2 < 3) 3 else 0
        val part5 = "Typ$y"
        val flag = "$part1{$part2$part3$part4$part5}"
        return flag
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val arrayNames: Array<String> = resources.getStringArray(R.array.dragon_array)
        val random = Random.Default
        val index = random.nextInt(0,arrayNames.size)
        val imageName = arrayNames[index]
        val myButton: Button = findViewById(R.id.button)
        val imageView: ImageView = findViewById(R.id.imageView)
        myButton.setOnClickListener {
            // Code to execute when the button is clicked
            val newIndex = random.nextInt(0,arrayNames.size)
            val newImageName = arrayNames[newIndex]
            val resourceId = resources.getIdentifier(newImageName, "drawable", packageName)
            if (resourceId != 0) {
                imageView.setImageResource(resourceId)
            } else {
                // Handle the case where the image is not found
                // For example, display a placeholder or log an error
                println("Image not found: $imageName")
            }
            val flag = createFlag()
        }
}
    }