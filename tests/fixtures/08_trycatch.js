function risky(x) {
  try {
    if (x < 0) throw new Error("negative");
    return Math.sqrt(x);
  } catch (e) {
    console.log("caught:", e.message);
    return 0;
  } finally {
    console.log("done with", x);
  }
}
risky(16);
risky(-1);
