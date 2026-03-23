// Update clock to simulate the precise timer shown in the concept
function updateClock() {
    const clockElement = document.getElementById('clock');
    if (!clockElement) return;

    const now = new Date();
    
    // Formatting hours, minutes, seconds to ensure double digits
    const hh = String(now.getHours()).padStart(2, '0');
    const mm = String(now.getMinutes()).padStart(2, '0');
    const ss = String(now.getSeconds()).padStart(2, '0');
    
    // Determine timezone abbreviation (defaults to IST per design or dynamically based on locale)
    // The design has exactly "11:06:20 IST" layout. We'll simulate that layout.
    
    // Fetch user's local timezone short name
    const tzMatch = new Intl.DateTimeFormat('en-US', { timeZoneName: 'short' }).formatToParts(now).find(p => p.type === 'timeZoneName');
    const tzName = tzMatch ? tzMatch.value : 'IST';
    
    const timeString = `${hh}:${mm}:${ss} ${tzName}`;
    
    clockElement.textContent = timeString;
}

// Initial Call
updateClock();
// Update every second
setInterval(updateClock, 1000);

// Basic entry animation hooks could be added here
document.addEventListener('DOMContentLoaded', () => {
    // Add visual fade in smoothly
    document.body.style.opacity = 0;
    document.body.style.transition = 'opacity 0.8s ease-in-out';
    setTimeout(() => {
        document.body.style.opacity = 1;
    }, 50);
});
