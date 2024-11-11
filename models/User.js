// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Transaction schema
const transactionSchema = new mongoose.Schema({
    date_time: { type: Date, required: true },
    type: { type: String, enum: ['credit', 'debit'], required: true },
    frmto: { type: String, required: true },
    amount: { type: Number, required: true },
    note: { type: String },
    photoId: { type: String }
    // photoId: { type: mongoose.Schema.Types.ObjectId, ref: 'File' } // Reference to GridFS file
});

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    number: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    cur_month_trans: { type: [transactionSchema], default: [] },
    cur_month_credit: { type: Number, default: 0 },
    cur_month_debit: { type: Number, default: 0 },
    cur_month_balance: { type: Number, default: 0 },
    tot_trans: { type: [transactionSchema], default: [] },
    total_credit: { type: Number, default: 0 },
    total_debit: { type: Number, default: 0 },
    total_balance: { type: Number, default: 0 }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

module.exports = mongoose.model('User', userSchema);
