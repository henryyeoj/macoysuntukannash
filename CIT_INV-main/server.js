const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
// Serves static files if Vercel routing misses them
app.use(express.static(path.join(__dirname))); 

// --- DATABASE CONNECTION ---
// Updated to the correct UA-CITINV cluster and added /cit_vault database target
const dbURI = 'mongodb+srv://admin:admin@ua-citinv.k3it38i.mongodb.net/cit_vault?appName=UA-CITINV';

mongoose.connect(dbURI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.log('❌ MongoDB Connection Error:', err));

// --- SCHEMAS ---
const Config = mongoose.model('Config', new mongoose.Schema({ pin: String }));
const Item = mongoose.model('Item', new mongoose.Schema({
    equipment: String,
    category: String, // NEW: Added category field
    description: String,
    price: Number,
    serials: [String],
    status: String,
    borrower: String,
    returnDate: String
}));
const Log = mongoose.model('Log', new mongoose.Schema({
    action: String,
    status: String,
    timestamp: String
}));

// --- API ROUTES ---
app.get('/api/config', async (req, res) => {
    let config = await Config.findOne() || await new Config({ pin: 'admin' }).save();
    res.json(config);
});

app.put('/api/config', async (req, res) => {
    const config = await Config.findOneAndUpdate({}, { pin: req.body.pin }, { new: true });
    res.json(config);
});

app.get('/api/items', async (req, res) => res.json(await Item.find()));

app.post('/api/items', async (req, res) => res.json(await new Item(req.body).save()));

app.put('/api/items/:id', async (req, res) => {
    res.json(await Item.findByIdAndUpdate(req.params.id, req.body, { new: true }));
});

app.delete('/api/items/:id', async (req, res) => {
    await Item.findByIdAndDelete(req.params.id);
    res.json({ message: 'Deleted' });
});

app.get('/api/logs', async (req, res) => res.json(await Log.find().sort({ _id: -1 })));

app.post('/api/logs', async (req, res) => res.json(await new Log(req.body).save()));

// --- FRONTEND CATCH-ALL ---
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// --- PORT (For local testing only) ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));

// CRITICAL: Export for Vercel's serverless engine
module.exports = app;