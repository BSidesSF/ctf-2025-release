tarnation.tar.xz is an XZ-compressed chain of tar achives. This is legal in the tar format.

There are three "revisions" of the flag image, all stored as the name `.`. The middle one is the true flag:

    $ tar -Jtiv -f tarnation.tar.xz
    -rw-r--r-- 1000/1000    173262 2025-04-15 18:26 drag_1.jpg
    -rw-r--r-- 1000/1000    173054 2025-04-15 18:26 drag_2.jpg
    -rw-r--r-- 1000/1000    173054 2025-04-15 18:26 drag_2.jpg
    -rw-r--r-- 1000/1000     64541 2025-04-15 18:19 .
    -rw-r--r-- 1000/1000     76418 2025-04-15 18:21 .
    -rw-r--r-- 1000/1000     64541 2025-04-15 18:19 .
    -rw-r--r-- 1000/1000    143056 2025-04-15 18:26 drag_3.jpg


You can extract a specific occurence of a file, in this case the flag, with `$ tar -Jiv -x '.' -f tarnation.tar.xz -O --occurrence=2 > flag.jpg`. Note using stdout just bypasses the error of trying to extract `.` which collides with the CWD name.

File carving will also solve this challenge.

flag: CTF{tarrible_format}
