const express = require('express');
const userRoute = require('./routes/userRoute');
const app = express();
const dotenv = require('dotenv');
const mongoose = require('mongoose');

dotenv.config({ path: './config.env' });

const DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASS);

mongoose.connect(DB, {}).then(() => console.log(`DATABASE connect successfully!`));

app.use(express.json());
app.use('/back', userRoute);

PORT = process.env.PORT || 8000
app.listen(PORT, () => {
    console.log(`App listening on port ${PORT}...`);
});