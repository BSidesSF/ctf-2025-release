const cards = document.querySelectorAll('.dragon-card');

// Mostly for show, flips over all the cards at once 
const revealButton = document.querySelector('.reveal-button');
revealButton.addEventListener('click', function() {
    flipCard(); // Call the flipCard function
  });
function flipCard() {
  cards.forEach(card => {
  card.classList.add('flip');});
}

// For zoomed in high-res view 
let card;

// Add on click listener to fetch the high-res image 
cards.forEach(card => card.addEventListener('click', zoomImage));

function zoomImage(event) {
  const zoomId = event.target.dataset.id;
  window.open(`/image?id=${zoomId}`);
}

