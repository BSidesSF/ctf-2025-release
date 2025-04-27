import os
from PIL import Image
from pathlib import Path

def replace_letters_with_pngs(input_text, png_extension=".png"):
    """
    Replaces letters in a string with corresponding PNG images.

    Args:
        input_text: The input string.
        png_extension: The file extension of the PNG images (default: ".png").
    """

    output_images = []
    line = 1 
    png_folder = "png_letters/"
    text = ""
    for char in input_text:
        text += char
        if 'a' <= char <= 'z' or 'A' <= char <= 'Z':  # Check if it's a letter
            char = char.upper()
            png_filename = os.path.join(png_folder + char + png_extension)
            output_images = image_append(png_filename, output_images)
        elif char == " ":
            png_filename = os.path.join("Space" + png_extension)
            output_images = image_append(png_folder + png_filename, output_images)
        elif char == ".":
            png_filename = os.path.join("Period" + png_extension)
            output_images = image_append(png_folder + png_filename, output_images)
        elif char == ",":
            png_filename = os.path.join("Comma" + png_extension)
            output_images = image_append(png_folder + png_filename, output_images)
        elif char == "{":
            png_filename = os.path.join("Curly-open" + png_extension)
            output_images = image_append(png_folder + png_filename, output_images)
        elif char == "}":
            png_filename = os.path.join("Curly-close" + png_extension)
            output_images = image_append(png_folder + png_filename, output_images)
        # When new line, generate the image
        elif char == "\n":
            print(text)
            output_path = str(line) + ".png" 
            create_horizontal_image(output_images, output_path)
            ## Reset the output image array
            output_images = []
            ## Increment the output file suffix
            line += 1
            ## Reset the text, this is for testing 
            text = "" 
        else:
            print(f"Invalid character in : {char}")

def image_append(png_filename, output_images):
    if os.path.exists(png_filename):
        try:
            img = Image.open(png_filename)
            output_images.append(img)
        except Exception as e:
            print(f"Error opening image {png_filename}: {e}")
            output_images.append(char) #if image fails, add the original char.
    else:
        print(f"PNG file not found: {png_filename}")
        output_images.append(char) # if file not found, add the original char.
    return output_images

def create_horizontal_image(image_list, output_path="output.png"):
    """ 
    Creates a single horizontal image by concatenating a list of images.

    Args:
        image_list: A list of PIL Image objects or characters.
        output_path: The path to save the combined image.
    """
    images_to_concat = []
    widths = []
    heights = []

    for item in image_list:
      if isinstance(item, Image.Image):
        images_to_concat.append(item)
        widths.append(item.width)
        heights.append(item.height)
      else:
        print(f"Warning: Cannot concatenate non-image item: {item}")

    if not images_to_concat:
        print("No valid images to concatenate.")
        return

    max_height = max(heights)
    total_width = sum(widths)

    new_image = Image.new("RGBA", (total_width, max_height), (0, 0, 0, 0))  # Transparent background

    x_offset = 0
    for img in images_to_concat:
        new_image.paste(img, (x_offset, (max_height - img.height) // 2))  # Center vertically
        x_offset += img.width

    new_image.save("outputs/" + output_path)
    print(f"Combined image saved to {output_path}")

def create_vertical_image(input_dir="outputs",output_path="output_vertical.png"):
    """
    Creates a single vertical image by concatenating a list of images.

    Args:
        input_dir: Directory that has the images to be combined
        output_path: The path to save the combined image.
    """
    # Order the files by creation time
    image_files = sorted(Path(input_dir).iterdir(), key=os.path.getmtime)
    if not image_files:
        print(f"No images found in {input_dir}")
        return
    images = []
    widths = []
    heights = []
    for filename in image_files:
        print(f"Reading file: {filename}")
        filepath = os.path.join(filename)
        try:
            img = Image.open(filepath)
            images.append(img)
            widths.append(img.width)
            heights.append(img.height)
        except Exception as e:
            print(f"Error opening image {filepath}: {e}")
            return #stop if any image fails

    if not images:
        print("No valid images to combine.")
        return

    max_width = max(widths)
    total_height = sum(heights)

    new_image = Image.new("RGBA", (max_width, total_height), (0, 0, 0, 0))  # RGB for most images

    y_offset = 0
    for img in images:
        new_image.paste(img, ((max_width - img.width) // 2, y_offset))  # Center horizontally
        y_offset += img.height

    new_image.save(output_path)
    print(f"Combined vertical image saved to {output_path}")

def read_file(filepath):
    """
    Reads a file from disk and returns its content as a string.

    Args:
        filepath: The path to the file.

    Returns:
        The file content as a string, or None if an error occurs.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as file:  # 'r' for read, encoding for text
            content = file.read()
            return content
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None
    except PermissionError:
        print(f"Error: Permission denied for {filepath}")
        return None
    except UnicodeDecodeError:
        print(f"Error: Could not decode file {filepath}. Try a different encoding.")
        return None
    except Exception as e: # catch other errors.
        print(f"An unexpected error occurred: {e}")
        return None

# Read the spell file
file_path = "spell.txt"  # Replace with the actual file path
file_content = read_file(file_path)

if file_content is not None:
    print("File content:")
    print(file_content)


# Convert the spell into image
input_text = file_content
output_dir = "outputs"  # Replace with the actual directory containing your PNG files
os.makedirs(output_dir, exist_ok=True) #creates the folder if it does not exist.
replace_letters_with_pngs(input_text)
create_vertical_image()