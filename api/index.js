// api/index.js
const app = require('../src/app');

module.exports = (req, res) => {
  // Just pass through to Express app
  return app(req, res);
};