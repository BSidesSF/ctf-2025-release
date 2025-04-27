# HEY Stop looking here! There be dragons! Go look at ../../../../../../../../flag.txt like you're supposed to, hacker!

require 'webrick'
require 'cgi'
require 'socket'

server = ::TCPServer.new('0.0.0.0', 4000)

puts "Server ready: #{ server.inspect }"
loop do
  Thread.start(server.accept) do |client|
    puts "Accepted connection from #{ client.remote_address.getnameinfo.join(':') }"

    request_line = client.gets

    if request_line.nil?
      next
    end

    unless request_line.strip =~ /^[A-Z]+ ([^ ]+) ([^ ]+)$/i
      client.write "HTTP/400 Bad Request\r\n\r\n"
      next
    end

    verb = $0
    original_path = CGI.unescape($1)
    protocol = $2

    puts "Request line: #{ request_line }"

    path = "./#{ original_path[1..] }"

    puts "Path: #{ path }"

    result = 'HTTP/1.1 200 OK'
    content_type = "text/plain"
    if File.file?(path)
      data = File.read(path)

      if path.include?('.html')
        content_type = "text/html"
      end
    elsif File.directory?(path)
      if File.file?(File.join(path, 'index.html'))
        data = File.read(File.join(path, 'index.html'))
        content_type = "text/html"
      else
        listing = Dir.entries(path)
        content_type = "text/html"

        # Create the HTML header
        data = "<html>\n"
        data += "  <head>\n"
        data += "    <title>Directory Listing</title>\n"
        data += "    <style>\n"
        data += "      body {\n"
        data += "        font-family: Arial, sans-serif;\n"
        data += "      }\n"
        data += "      table {\n"
        data += "        border-collapse: collapse;\n"
        data += "      }\n"
        data += "      th, td {\n"
        data += "        border: 1px solid #ddd;\n"
        data += "        padding: 8px;\n"
        data += "      }\n"
        data += "    </style>\n"
        data += "  </head>\n"
        data += "  <body>\n"
        data += "    <h1>Directory Listing for #{ Dir.pwd }</h1>\n"
        data += "    <table>\n"
        data += "      <tr>\n"
        data += "        <th>Name</th>\n"
        data += "        <th>Type</th>\n"
        data += "      </tr>\n"

        # Add each directory entry to the HTML table
        listing.each do |entry|
          next if entry == '.' || entry == '..'

          data += "      <tr>\n"
          data += "        <td><a href=\"#{File.join(original_path, entry)}\">#{entry}</a></td>\n"
          data += "        <td>#{File.directory?(entry) ? 'Directory' : 'File'}</td>\n"
          data += "      </tr>\n"
        end

        # Close the HTML tags
        data += "    </table>\n"
        data += "  </body>\n"
        data += "</html>\n"
      end
    else
      data = "Oops, that page wasn't found! Go back to <a href=\"/\">the starting page</a>?"
      result = 'HTTP/1.1 404 Not Found'
      content_type = 'text/html'
    end

    client.write([
      result,
      "Content-Type: #{ content_type }",
      "Last-Modified: #{ Time.now.httpdate }",
      "Date: #{ Time.now.httpdate }",
      'Connection: close',
      "Content-Length: #{ data.length }",
      '',
      data
    ].join("\r\n"))
  rescue ::StandardError => e
    puts "Oopsie: #{ e }"
    puts e.backtrace
  ensure
    client.close
  end
end
