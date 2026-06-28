import server from "./api/ws.ts";
const PORT = Number(process.env.PORT) || 3000;
server.listen(PORT).on("listening", () => {
  console.log(`Server is listening at http://localhost:${PORT}`);
});
