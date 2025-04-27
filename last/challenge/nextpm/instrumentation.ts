export async function register() {
  console.log("starting instrumentation, environment", process.env.NEXT_RUNTIME);
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const data = await import('./lib/data');
    data.setupUsers();
    console.log("finishing instrumentation");
  }
}
