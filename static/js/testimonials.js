// Testimonials Data and Slider Functionality

// Sample testimonial data
const testimonials = [
  {
    id: 1,
    name: "Neha Gupta",
    role: "Designer",
    image: "https://images.pexels.com/photos/774909/pexels-photo-774909.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=2",
    content: "FastMedBooking has been a lifesaver! I was able to book an appointment with a dermatologist instantly when I had an allergic reaction. The process was so smooth and the reminder system is fantastic."
  },
  {
    id: 2,
    name: "Ravi Teja",
    role: "Software Engineer",
    image: "https://images.pexels.com/photos/220453/pexels-photo-220453.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=2",
    content: "As someone with a busy schedule, finding time to visit a doctor was always challenging. FastMedBooking solved this problem completely. I can find and book appointments on my lunch break in just a few clicks!"
  },
  {
    id: 3,
    name: "Sunita Patel",
    role: "Teacher",
    image: "https://images.pexels.com/photos/1587009/pexels-photo-1587009.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=2",
    content: "The convenience of managing my family's medical appointments through one platform is incredible. I can keep track of my children's vaccinations and my elderly parents' check-ups all in one place."
  },
  {
    id: 4,
    name: "Arjun Khanna",
    role: "Entrepreneur",
    image: "https://images.pexels.com/photos/614810/pexels-photo-614810.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=2",
    content: "Finding a specialist for my chronic condition used to be a nightmare. Thanks to FastMedBooking, I found an excellent doctor who had immediate availability. The detailed doctor profiles helped me make an informed choice."
  }
];

// Variables for testimonial slider
let currentTestimonialIndex = 0;
const testimonialSlider = document.getElementById('testimonialSlider');
const prevTestimonialBtn = document.getElementById('prevTestimonial');
const nextTestimonialBtn = document.getElementById('nextTestimonial');

// Function to render testimonials
function renderTestimonials() {
  if (!testimonialSlider) return;
  
  testimonialSlider.innerHTML = '';
  
  // Create testimonial slide
  const testimonial = testimonials[currentTestimonialIndex];
  const slide = document.createElement('div');
  slide.className = 'testimonial-slide';
  
  slide.innerHTML = `
    <img src="${testimonial.image}" alt="${testimonial.name}" class="testimonial-image">
    <div class="testimonial-content">
      <p>${testimonial.content}</p>
      <h4 class="testimonial-author">${testimonial.name}</h4>
      <p class="testimonial-role">${testimonial.role}</p>
    </div>
  `;
  
  testimonialSlider.appendChild(slide);
  
  // Add fade-in animation
  slide.style.opacity = '0';
  setTimeout(() => {
    slide.style.transition = 'opacity 0.5s ease';
    slide.style.opacity = '1';
  }, 10);
}

// Function to show the next testimonial
function showNextTestimonial() {
  currentTestimonialIndex++;
  if (currentTestimonialIndex >= testimonials.length) {
    currentTestimonialIndex = 0;
  }
  renderTestimonials();
}

// Function to show the previous testimonial
function showPrevTestimonial() {
  currentTestimonialIndex--;
  if (currentTestimonialIndex < 0) {
    currentTestimonialIndex = testimonials.length - 1;
  }
  renderTestimonials();
}

// Initialize testimonials and add event listeners
document.addEventListener('DOMContentLoaded', () => {
  renderTestimonials();
  
  if (prevTestimonialBtn) {
    prevTestimonialBtn.addEventListener('click', showPrevTestimonial);
  }
  
  if (nextTestimonialBtn) {
    nextTestimonialBtn.addEventListener('click', showNextTestimonial);
  }
  
  // Auto-rotate testimonials every 7 seconds
  setInterval(showNextTestimonial, 7000);
});