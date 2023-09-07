const express = require('express');
const app = express();
const port = 3000;

// Define a route for the root URL ("/") that responds with "Hello, World!"
app.get('/', (req, res) => {
    res.send('Hello, World!');
});

// Start the server and listen on the specified port
const server = app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

module.exports = server; // Export the server instance
