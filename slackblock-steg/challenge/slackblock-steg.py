from flask import Flask, request, render_template_string
from PIL import Image
import io
import base64

verb = False

def get_jpeg_dimensions(img_data):
    """
    Extract width and height from JPEG binary stream without using external libraries.
    """
    img_data.seek(0)  # Ensure we're at the start
    data = img_data.read()  # Read the binary data

    if data[:4] == b'\x89PNG':
        return True, "A PNG is not a JPEG", 0, 0

    if data[:2] != b'\xFF\xD8':
        return True, "Not a valid JPEG file", 0, 0

    idx = 2  # Start after JPEG magic number

    while idx < len(data):
        # Find marker (0xFF followed by a non-FF byte)
        while data[idx] == 0xFF:
            idx += 1
        marker = data[idx]
        idx += 1

        # Stop at Start of Frame (SOF) markers that define image dimensions
        if 0xC0 <= marker <= 0xC2:  # Covers SOF0 (Baseline), SOF2 (Progressive), etc.
            height = int.from_bytes(data[idx+3:idx+5], 'big')
            width = int.from_bytes(data[idx+5:idx+7], 'big')


            return False, "", width, height

        # Skip the segment (Length field: next two bytes indicate size)
        segment_length = int.from_bytes(data[idx:idx+2], 'big')
        idx += segment_length

    return True, "Unable to find the S0F segment with image dimensions", 0, 0


def set_jpeg_dimensions(img_data, wh):
    """
    Extract width and height from JPEG binary stream without using external libraries.
    """
    img_data.seek(0)
    data = img_data.read()

    idx = 2

    while idx < len(data):

        while data[idx] == 0xFF:
            idx += 1
        marker = data[idx]
        idx += 1

        if 0xC0 <= marker <= 0xC2:
            img_data.seek(idx + 3)
            img_data.write(wh[1].to_bytes(2, 'big'))
            img_data.write(wh[0].to_bytes(2, 'big'))

            return

        segment_length = int.from_bytes(data[idx:idx+2], 'big')
        idx += segment_length

    return


def bytes_to_bits(bs):

    bits = []

    for b in bs:
        for i in range(7, -1, -1):
            bits.append(((1 << i) & b) >> i)

    return bits

def bits_to_bytes(bits):

    byte_l = []

    for n in range(0, len(bits) // 8):
        byte_num = 0
        for b in range(8):
            byte_num |= bits[(n * 8) + b] << (7 - b)

        byte_l.append(byte_num)

    return bytes(byte_l)


app = Flask(__name__)

HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>slackblock-steg</title>
</head>
<body>
    <h2>slackblock-steg</h2>
    <form action="/" method="post" enctype="multipart/form-data">
    <label for="file">Choose JPG:</label>
    <input type="file" name="jpg" accept="image/jpeg" required><br><br>

    <label for="key">Key:</label>
    <input type="text" name="key" size="32"{% if key %} value="{{ key }}"{% endif %}><br><br>

    <label for="message">Message:</label>
    <input type="text" name="message" size="64"{% if message %} value="{{ message }}"{% endif %}><br><br>

    <button type="submit" name="action" value="retrieve">Retrieve Message</button>
    <button type="submit" name="action" value="set">Set Message</button>
    </form>
    {% if err_msg %}
        <h2><font color="#AA0000">Error: {{ err_msg }}</font></h2>
    {% endif %}
    {% if img_data %}
        <h2>slackblock-steg encoded image:</h2>
        <img src="data:image/jpeg;base64,{{ img_data }}" alt="Modified Image" filename="msg.jpg">
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def upload_file():
    img_data = None
    jpg = None
    action = None
    key = None
    message = None
    err_msg = None
    if request.method == "POST":
        jpg = request.files.get("jpg")
        action = request.form.get("action")  # "set" or "retrieve"
        key = request.form.get("key")
        message = request.form.get("message")

        if verb:
            print(f"Action: {action}")
            print(f"Key: {key}")
            print(f"Message: {message}")

        if jpg is None:
            err_msg = 'A JPG file must be provided'

        if action is None or not action in ("set", "retrieve"):
            err_msg = 'The form action must be "set" or "retrieve"'

        if not key is None and len(key) > 255:
            err_msg = "The key length must be less than 256 bytes"

        if not action is None and action == "set" and not message is None and len(message) > 255:
            err_msg = "The message length must be less than 256 bytes"

        if not err_msg is None:
            return render_template_string(HTML_TEMPLATE, err_msg=err_msg, img_data=img_data, message=message, key=key)

        if key is None:
            key = ""

        if message is None:
            message = ""


        if not jpg is None:
            jpg_io = io.BytesIO(jpg.read())

            err, err_msg, w, h = get_jpeg_dimensions(jpg_io)

            if err:
                return render_template_string(HTML_TEMPLATE, err_msg=err_msg, img_data=img_data, message=message, key=key)

            nw, nh = (w + 7) & ~7, (h + 7) & ~7

            if h != nh or w != nw:

                if verb:
                    print(f"Old size {w}x{h}; new size {nw}x{nh}")

                if (nw - w) > (nh - h):
                    if verb:
                        print("Will encode top-down")
                    # Encode top down
                    cp = (w, 0)
                    pd = (0, 1)
                    ml = nh
                else:
                    if verb:
                        print("Will encode left-to-right")
                    # Encode left to right
                    cp = (0, h)
                    pd = (1, 0)
                    ml = nw

                set_jpeg_dimensions(jpg_io, (nw, nh))
                jpg_io.seek(0)
                img = Image.open(jpg_io)
                pixels = img.load()

                if action == "set":
                    bstr = bytes_to_bits(b'88' + len(key).to_bytes(1, 'big') + bytes(key, 'utf-8') + len(message).to_bytes(1, 'big') + bytes(message, 'utf-8'))

                    if len(bstr) > ml:
                        err_msg = f'Unable to store {len(bstr)} bits; maximum bits available in this image is {ml}!'
                        return render_template_string(HTML_TEMPLATE, err_msg=err_msg, img_data=img_data, message=message, key=key)

                    # Store the message bit-by-bit in black (0) / white (1) pixels
                    for b in bstr:
                        pixels[cp] = (255 * b, 255 * b, 255 * b)
                        cp = (cp[0] + pd[0], cp[1] + pd[1])

                    # Save modified image to memory with the same quantization tables
                    img_bytes = io.BytesIO()
                    img.save(img_bytes, format="JPEG", quality="keep")

                    # Re-hide the slack pixels
                    set_jpeg_dimensions(img_bytes, (w, h))

                    img_bytes.seek(0)
                    img_data = base64.b64encode(img_bytes.read()).decode('utf-8')

                if action == "retrieve":
                    kbstr = bytes_to_bits(b'88' + len(key).to_bytes(1, 'big') + bytes(key, 'utf-8'))

                    if len(kbstr) + 1 > ml:
                        err_msg = f'Unable retrieve message; key + header bits ({len(kbstr) + 1}) exceeds maximum bits available in this image ({ml})!'
                        return render_template_string(HTML_TEMPLATE, err_msg=err_msg, img_data=img_data, message=message, key=key)

                    em = [] # Embedded message bit list

                    for _ in range(ml):
                        p = pixels[cp]
                        if sum(p) <= 127 * 3:
                            b = 0
                        else:
                            b = 1
                        em.append(b)
                        cp = (cp[0] + pd[0], cp[1] + pd[1])

                    if em[:len(kbstr)] != kbstr:
                        err_msg = f'Unable retrieve message; key does not match embedded key!'
                        return render_template_string(HTML_TEMPLATE, err_msg=err_msg, img_data=img_data, message=message, key=key)

                    mbytes = bits_to_bytes(em[len(kbstr):])

                    mlen = int(mbytes[0])

                    if mlen + 1 > len(mbytes):
                        err_msg = f'Unable to retrieve message; embedded message appears to be truncated!'
                        return render_template_string(HTML_TEMPLATE, err_msg=err_msg, img_data=img_data, message=message, key=key)

                    message = mbytes[1:(mlen + 1)].decode("utf-8")

            else:
                err_msg = "There isn't any slack space in this image to hide data."



    return render_template_string(HTML_TEMPLATE, err_msg=err_msg, img_data=img_data, message=message, key=key)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8888)
