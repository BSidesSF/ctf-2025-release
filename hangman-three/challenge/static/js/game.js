const alphabetButtons = document.querySelectorAll('.alphabet');
  const guessedLetterInput = document.getElementById('guessedLetter');
  const guessForm = document.getElementById('guessForm');

  alphabetButtons.forEach(button => {
    button.addEventListener('click', function(event) {
      event.preventDefault(); // Prevent the default button behavior (if inside a form and not type="submit")

      const letter = this.dataset.value;
      guessedLetterInput.value = letter; // Set the value of the hidden input

      guessForm.submit(); // Submit the form
    });
  });