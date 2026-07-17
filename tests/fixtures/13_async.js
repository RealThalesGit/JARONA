async function main() {
  const data = await fetch("/api");
  return data.id;
}
main().then(console.log).catch(console.error);
