<?php
header('Content-Type: application/json');

// Ensure the request method is POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $input = file_get_contents('php://input');
  $data = json_decode($input, true);

  // Validate the JSON input
  if ($data) {
    // Validate
    if(!preg_match('/[0-9]*/', $data['gold']) || !preg_match('/[0-9]*/', $data['gems']) || !preg_match('/[0-9]*/', $data['artifacts'])) {
      echo json_encode([
        "status" => "error",
        "message" => "Fire-scorched parchment detected - invalid submission"
      ]);
      exit(1);
    } else {
      if($data['hoardType'] == 'gold') {
        $valuation = $data['gold'] * 100;
      } elseif($data['hoardType'] == 'gemstone') {
        $valuation = $data['gems'] * 1000;
      } elseif($data['hoardType'] == 'artifact') {
        $valuation = shell_exec("/app/valuate-hoard '" . $data['gold'] . "' '" . $data['gems'] . "' '" . $data['artifacts'] . "'");
      } else {
        http_response_code(400);
        echo json_encode([
          "status" => "error",
          "message" => "Fire-scorched parchment detected - invalid submission"
        ]);
        exit(1);
      }

      echo json_encode([
        "status" => "success",
        "message" => "Hoard valuation logged and valued at <tt>$valuation</tt>"
      ]);
    }
  } else {
      // Handle invalid JSON input
      http_response_code(400);
      echo json_encode([
        "status" => "error",
        "message" => "Fire-scorched parchment detected - invalid submission"
      ]);
  }
} else {
  // Handle non-POST requests
  http_response_code(405); // Method Not Allowed
  echo json_encode([
    "status" => "error",
    "message" => "Only POST requests are allowed for hoard valuation"
  ]);
}
?>
