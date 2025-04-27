# encoding: ASCII-8bit

require 'tempfile'

FLAG = 'CTF{hope-you-enjoyed-this-one}'

# Set this pointer to the end of the file, because we need to know where the
# code is
bugme = File.read('bug-me').force_encoding('ASCII-8BIT')
bugme.gsub!("\x37\x13\x37\x13", [bugme.length].pack('V'))

# We're going to incorporate a checksum of main() to prevent shenanigans
disas_main = `gdb -q -batch -ex 'file ./bug-me' -ex 'disassemble main' -ex 'quit'`
             .split(/\n/)
             .select { |line| line =~ /0x000/ }
             .map { |line| line =~ /(0x000[0-9a-fA-F]*)/; Regexp.last_match(0) }

main_start = disas_main[0].to_i(16)
main_end = disas_main[-1].to_i(16)

checksum = 0
bugme.bytes[main_start..main_end].each do |b|
  checksum = (checksum + b) % 256
end

puts 'Calculated main() checksum = 0x%02x' % checksum

# Encode the flag onto the end of the binary
FLAG.chars.each do |c|
  Tempfile.create(['matcher', '.c']) do |infile|
    a = c.ord % 5
    b = c.ord % 7
    c = c.ord % 11

    infile.puts('int match(char c) {')
    infile.puts("  return !((c % 5 == #{ a }) && (c % 7 == #{ b }) && (c % 11 == #{ c }));")
    infile.puts('}')
    infile.close

    Tempfile.create(['out', '.o']) do |outfile|
      outfile.close

      system("gcc -c -Os -no-pie -Wall -o \"#{ outfile.to_path }\" \"#{ infile.to_path }\"")

      # I'm sure there's a better way to do this, but I'm also sure I don't care
      disas = `objdump -d \"#{ outfile.to_path }\"`
              .split(/\n/)
              .map do |line|
                if line =~ /[0-9a-f]:\s+(([0-9a-f]{2} )+)+/i
                  Regexp.last_match(1).gsub(/ /, '')
                else
                  ''
                end
              end

      rng = rand(1..255)
      disas = [disas.join('')].pack('H*').bytes.each_with_index.map { |new_b, i| (new_b ^ rng ^ (i << 2) ^ checksum).chr }.join

      if disas.length > 255
        raise "Disassembly is too long! Max length is 255, this is #{ disas.length }"
      end

      # puts disas.bytes.map { |d| "\\x%02x" % d }.join
      bugme << [rng, disas.length, disas].pack('CCa*')
    end
  end
end

File.write('bug-me', bugme)
