function dayName(n) {
  switch (n) {
    case 0: return "Sun";
    case 6: return "Sat";
    default: return "Weekday";
  }
}
console.log(dayName(3));
