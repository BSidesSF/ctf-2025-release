# Magic

The challenge name and prompt suggest there's something wrong with the magic
bytes of the image, since it won't open.

You can use a tool like `xxd` or Bless to examine and edit the hex of the file. 

The first few bytes of a file are called "magic bytes" and they dictate the
file's type. For PNG images, the header is supposed to be `8950 4e47`, however,
`magic.png` starts with `616e 7368`. 

Changing the header to the correct magic bytes fixes the issue.
