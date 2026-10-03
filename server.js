const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = 3000;

// Temporary in-memory state
const users = [];
const queue = [];
const allocations = [];

let totalSeats = 500;
let remainingSeats = 500;

app.get("/", (req, res) => {
    res.json({
        message: "Fair Drop backend is running!"
    });
});

// Test user joining the drop
app.post("/api/join", (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({
            error: "userId is required"
        });
    }

    const user = {
        userId,
        type: "unknown",
        status: "pending",
        joinedAt: new Date()
    };

    users.push(user);
    queue.push(user);

    res.json({
        message: "User entered the drop",
        user
    });
});

// Get current statistics
app.get("/api/stats", (req, res) => {
    res.json({
        totalSeats,
        remainingSeats,
        totalUsers: users.length,
        queueLength: queue.length,
        allocations: allocations.length
    });
});

app.listen(PORT, () => {
    console.log(`Fair Drop server running on http://localhost:${PORT}`);
});
