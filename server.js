const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = 3000;

app.get("/", (req, res) => {
    res.json({
        message: "Fair Drop backend is running!"
    });
});

app.listen(PORT, () => {
    console.log(`Fair Drop server running on http://localhost:${PORT}`);
});
