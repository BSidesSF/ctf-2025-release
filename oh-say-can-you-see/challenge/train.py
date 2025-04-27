#!/usr/bin/env python3

import tensorflow as tf
from tensorflow.keras.preprocessing.image import ImageDataGenerator
from tensorflow.keras import layers, models

IMG_Y_SIZE = 256
IMG_X_SIZE = 256
BATCH_SIZE = 4

# Rescale and load images
datagen = ImageDataGenerator(rescale=1./255, validation_split=0.2)

train_data = datagen.flow_from_directory(
    'data',
    target_size=(IMG_Y_SIZE, IMG_X_SIZE),
    color_mode='grayscale',
    class_mode='sparse',
    batch_size=BATCH_SIZE,
    subset='training',
    shuffle=True
)

val_data = datagen.flow_from_directory(
    'data',
    target_size=(IMG_Y_SIZE, IMG_X_SIZE),
    color_mode='grayscale',
    class_mode='sparse',
    batch_size=BATCH_SIZE,
    subset='validation'
)

model = models.Sequential([
    layers.Input(shape=(IMG_Y_SIZE, IMG_X_SIZE, 1)),
    #layers.Conv2D(256, (3,3), activation='relu'),
    #layers.MaxPooling2D((2,2)),
    layers.Conv2D(32, (3,3), activation='relu'),
    #layers.MaxPooling2D((2,2)),
    layers.Flatten(),
    #layers.Dense(64, activation='relu'),
    layers.Dense(4)  # No activation; logits for use with SparseCategoricalCrossentropy(from_logits=True)
])

model.compile(optimizer='adam',
              loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
              metrics=['accuracy'])

history = model.fit(train_data, validation_data=val_data, epochs=10)

model.save("flagnet.keras")
