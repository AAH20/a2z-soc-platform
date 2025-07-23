const express = require('express');
const path = require('path');
const app = express();
const PORT = 8080;

// Serve static files from the dist directory
app.use(express.static(path.join(__dirname, 'dist')));

// Handle React Router - serve index.html for all routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🎨 Frontend server running on http://localhost:${PORT}`);
  console.log(`📁 Serving from: ${path.join(__dirname, 'dist')}`);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Frontend server shutting down...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 Frontend server shutting down...');
  process.exit(0);
}); 