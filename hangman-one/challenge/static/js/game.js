const alphabets = document.querySelectorAll('.alphabet');

// Add onclick listener
alphabets.forEach(alphabet => alphabet.addEventListener('click', sendRequest));

function updateLifeLost(lifeLostValue) {
    const lifeLostParagraph = document.querySelector('.life-lost');
    if (lifeLostParagraph) {
        lifeLostParagraph.textContent = `Lives Lost: ${lifeLostValue} of 4.`;
    } else {
        console.error("Could not find element with class 'life-lost'");
    }
}

function updateHangmanImage(lifeLostValue) {
  const hangmanImage = document.getElementById("hangman-image");
  if (hangmanImage) {
    hangmanImage.src = `/static/images/hangman-${lifeLostValue}.png`;
  } else {
    console.error("Could not find element with ID 'hangman-image'");
  }
}

function sendRequest(event) {
    // Disable the button that was clicked 
    const clickedButton = event.target;
    clickedButton.disabled = true;

    // Figure out which alphabet was pressed 
    const alphabetId = event.target.dataset.id;

    // Send the guess 
    $.get(`/guess?letter=${encodeURIComponent(alphabetId)}`, function(data, textStatus, jqXHR) {
        //const parsedData = JSON.parse(data);
        if (data.reload) {
            window.location.reload(); // Reload the page
        } else {
            updateLifeLost(data.life_lost)
            updateHangmanImage(data.life_lost)
            if (data.present === 'true') {
                data.positions.forEach(position => {
                    const letterDiv = document.querySelector(`.letter[data-id="${position}"]`);
                    if (letterDiv) {
                        letterDiv.textContent = `${data.letter}`;
                    } else {
                        console.log(`Div with data-id ${position} not found.`);
                    }
                });
            } else {
                // Handle the case where the letter is not present (e.g., display a message)
                newText = `Letter '${data.letter}' not present.`
                const outcomeDiv = document.querySelector(".outcome.alert.alert-info strong");
                if (outcomeDiv) {
                    outcomeDiv.textContent = newText;
                }
            }
        }
    }, "json"); // Specify data type as JSON
}