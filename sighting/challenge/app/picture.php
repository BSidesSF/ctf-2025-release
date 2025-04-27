<?php
// Check if the file parameter is provided
if (isset($_REQUEST['file'])) {
    $filePath = $_REQUEST['file'];

    // Check if the file exists and is readable
    if (file_exists($filePath) && is_readable($filePath)) {
        // Get the MIME type of the file
        $mimeType = mime_content_type($filePath);

        // Set the appropriate headers
        header("Content-Type: $mimeType");
        header("Content-Length: " . filesize($filePath));

        // Output the file contents
        readfile($filePath);
        exit;
    } else {
        // Handle the case where the file does not exist or is not readable
        header('HTTP/1.0 404 Not Found');
        echo "File not found or not readable.";
        exit;
    }
} else {
    // Handle the case where no file parameter is provided
    header('HTTP/1.0 400 Bad Request');
    echo "No file specified.";
    exit;
}
?>
