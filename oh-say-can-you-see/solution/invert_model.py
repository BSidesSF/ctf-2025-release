#!/usr/bin/env python3


import tensorflow as tf
from keras.models import load_model
import numpy as np

from PIL import Image
import os
import sys

MODEL = load_model(sys.argv[1])
CLASSES = 4
IMG_Y_SIZE = 256
IMG_X_SIZE = 256

# Define the loss object for sparse categorical crossentropy
loss_object = tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True)


def inversion(model, img, learning_rate, class_index):

    # Add uniform noise to image so we don't get stuck
    img_np_noise = np.array([np.clip(x + np.random.normal(3, 3), 0, 255) for x in img.numpy()])

    # Convert back to tensor
    img_noise = tf.convert_to_tensor(img_np_noise)

    # Use gradient tape to watch the image tensor
    with tf.GradientTape() as tape:
       tape.watch(img_noise)
       prediction = model(img_noise, training=False) # run img through the model
       loss = loss_object(tf.convert_to_tensor([class_index]), prediction)

       # Calculate gradient of loss for each pixel
       gradient = tape.gradient(loss, img_noise)

    # Subtract gradiant scaled by learning rate and clipped to proper range
    img = tf.clip_by_value(img_noise - learning_rate * gradient, 0, 255)

    return img


# Create output directory if it doesn't exist
output_dir = "generated_classes"
os.makedirs(output_dir, exist_ok=True)

for class_index in range(CLASSES):

    # Start out with all-black image
    cur_img = tf.convert_to_tensor(np.zeros((1, IMG_X_SIZE, IMG_Y_SIZE, 1)))

    for i in range(128):
        cur_img = inversion(MODEL, cur_img, 0.1, class_index)

    # Now turn tensor into an image
    img_np = cur_img.numpy()[0, :, :, 0] # Reshape into 2d array

    # Normalize values into the range 0 .. 255 by finding min and max
    img_min = img_np.min()
    img_max = img_np.max()
    img_norm = (img_np - img_min) / (img_max - img_min + 1e-8)  # Normalize to [0, 1]
    matrix_uint8 = (img_norm * 255).astype(np.uint8)            # Scale back into greyscale range

    pil_img = Image.fromarray(matrix_uint8, mode='L') # Mode L is grey
    output_path = os.path.join(output_dir, f"class_{class_index}.png")
    pil_img.save(output_path)
    print(f"Saved: {output_path}")

