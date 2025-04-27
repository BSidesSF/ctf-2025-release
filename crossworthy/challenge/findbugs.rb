bugs = File.read('bugs.txt').split("\n")
WORDS = File.read('/home/ron/tools/crosswords/wordlists/everything.txt')
  .split("\n")
  .map { |w| w.split(/;/)[0] }
  .select! { |w| w.length == 9 || w.length == 10 || w.length == 12 }
  .sort
  .uniq

bugs.each do |bug|
  words = WORDS.select { |word| word.include?(bug) && !word.start_with?(bug) && !word.end_with?(bug) }

  # if words.length > 0
  #   puts
  #   puts bug
  #   puts '---'
  #   puts words.join("\n")
  # end
  (bugs - [bug]).each do |bug2|
    words = WORDS.select { |word| word.include?(bug) && word.include?(bug2) }

    if words.length > 0
      puts
      puts "#{ bug } + #{ bug2 }"
      puts '---'
      puts words.join("\n")
    end
  end
end
