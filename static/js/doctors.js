// Doctors Data and Rendering

// Sample doctor data
const doctors = [
  {
    id: 1,
    name: "Dr. Aisha Sharma",
    specialty: "Cardiologist",
    image: "https://images.pexels.com/photos/7089629/pexels-photo-7089629.jpeg",
    rating: 4.9,
    reviews: 124,
    availability: "Available Today",
    experience: "15 years",
    hospital: "Heart Care Hospital",
    fee: "₹1200"
  },
  {
    id: 2,
    name: "Dr. Vikram Mehta",
    specialty: "Neurologist",
    image: "https://images.pexels.com/photos/8460157/pexels-photo-8460157.jpeg",
    rating: 4.8,
    reviews: 98,
    availability: "Available Tomorrow",
    experience: "12 years",
    hospital: "Brain & Spine Institute",
    fee: "₹1500"
  },
  {
    id: 3,
    name: "Dr. Priya Patel",
    specialty: "Dermatologist",
    image: "https://images.pexels.com/photos/7578816/pexels-photo-7578816.jpeg",
    rating: 4.7,
    reviews: 156,
    availability: "Available Today",
    experience: "8 years",
    hospital: "Skin Care Clinic",
    fee: "₹1000"
  },
  {
    id: 4,
    name: "Dr. Rajesh Kumar",
    specialty: "Orthopedic Surgeon",
    image: "https://images.pexels.com/photos/7088530/pexels-photo-7088530.jpeg",
    rating: 4.9,
    reviews: 210,
    availability: "Available in 2 days",
    experience: "20 years",
    hospital: "Joint Care Hospital",
    fee: "₹1800"
  }
];

// Function to render doctor cards
function renderDoctors() {
  const doctorsGrid = document.getElementById('doctorsGrid');
  if (!doctorsGrid) return;
  
  doctorsGrid.innerHTML = '';
  
  doctors.forEach(doctor => {
    const doctorCard = document.createElement('div');
    doctorCard.className = 'doctor-card';
    
    const stars = generateStars(doctor.rating);
    
    doctorCard.innerHTML = `
      <img src="${doctor.image}" alt="${doctor.name}" class="doctor-image">
      <div class="doctor-info">
        <h3 class="doctor-name">${doctor.name}</h3>
        <p class="doctor-specialty">${doctor.specialty}</p>
        <div class="doctor-rating">
          ${stars}
          <span>${doctor.rating} (${doctor.reviews} reviews)</span>
        </div>
        <p class="doctor-availability">${doctor.availability}</p>
        <p><strong>Experience:</strong> ${doctor.experience}</p>
        <p><strong>Hospital:</strong> ${doctor.hospital}</p>
        <p><strong>Consultation Fee:</strong> ${doctor.fee}</p>
        <button class="btn btn-primary doctor-button" data-doctor-id="${doctor.id}">Book Appointment</button>
      </div>
    `;
    
    doctorsGrid.appendChild(doctorCard);
  });
  
  // Add event listeners to book appointment buttons
  const bookButtons = document.querySelectorAll('.doctor-button');
  bookButtons.forEach(button => {
    button.addEventListener('click', () => {
      const doctorId = button.getAttribute('data-doctor-id');
      bookAppointment(doctorId);
    });
  });
}

// Generate star rating HTML
function generateStars(rating) {
  let stars = '';
  const fullStars = Math.floor(rating);
  const halfStar = rating % 1 >= 0.5;
  
  for (let i = 0; i < fullStars; i++) {
    stars += '<i class="fas fa-star"></i>';
  }
  
  if (halfStar) {
    stars += '<i class="fas fa-star-half-alt"></i>';
  }
  
  const emptyStars = 5 - fullStars - (halfStar ? 1 : 0);
  for (let i = 0; i < emptyStars; i++) {
    stars += '<i class="far fa-star"></i>';
  }
  
  return stars;
}

// Function to handle booking an appointment
function bookAppointment(doctorId) {
  const doctor = doctors.find(doc => doc.id === parseInt(doctorId));
  
  if (!doctor) return;
  
  // Check if user is logged in
  if (!currentUser) {
    loginModal.style.display = 'flex';
    return;
  }
  
  // If user is logged in, redirect to patient dashboard
  window.location.href = 'pages/patient-dashboard.html';
}

// Initialize doctors
document.addEventListener('DOMContentLoaded', renderDoctors);