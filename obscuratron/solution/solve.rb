# Encoding: ASCII-8bit

require 'digest'

original = File.read(File.join(__dir__, '..', 'challenge', 'src', 'memo.pdf')).force_encoding('ASCII-8bit')
encrypted = File.read(File.join(__dir__, '..', 'challenge', 'src', 'memo.pdf.enc')).force_encoding('ASCII-8bit')

key = 0xab
decrypted = (encrypted.bytes.map do |i|
  decrypted = (i ^ key)
  key = i
  decrypted.chr
end).join

puts "Original: #{ Digest::SHA256.hexdigest(original) }"
puts "Decrypted: #{ Digest::SHA256.hexdigest(decrypted) }"
puts

if original != decrypted
  path1 = File.join(__dir__, 'original.pdf')
  path2 = File.join(__dir__, 'broken.pdf')
  puts "Something changed in the decryption! Writing the files to #{ path1 } + #{ path2 }"
  File.write(path1, original)
  File.write(path2, decrypted)

  exit 1
end

puts "Looks good! (Though I can't validate the flag)"
