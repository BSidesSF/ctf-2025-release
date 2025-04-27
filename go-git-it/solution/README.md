# Solution

1. Viewing the webpage doesn't yield anything interesting so you can inspect the source code to find a dev note to unlist the git directory.
2. Navigating to the /git/ path lists out an exposed .git directory.
3. You can use `curl` or `wget` to download this directory and inspect it.
4. From inside the git directory, you can use the following command to see if any files have been deleted:

    ```bash
    git log --name-status
    ```

5. Once you have the commit ID, just run this command to get to the flag.

    ```bash
    git show <commit ID> -- <file path>
    ```
