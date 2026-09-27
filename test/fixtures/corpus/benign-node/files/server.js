const express = require('express');
const app = express();
app.get('/', (req, res) => res.json({ ok: true }));
app.listen(process.env.PORT || 3000);
