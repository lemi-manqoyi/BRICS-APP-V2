const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const session = require('express-session');

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());
app.use(helmet());

app.set('trust proxy', 1);
const csrfProtection = csrf({ cookie: true });

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  next();
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' },
  })
);

mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error(err));

const { Schema } = mongoose;

const countryMapping = {
  Brazil: { code: '+55', currency: 'BRL' },
  Russia: { code: '+7', currency: 'RUB' },
  India: { code: '+91', currency: 'INR' },
  China: { code: '+86', currency: 'CNY' },
  SouthAfrica: { code: '+27', currency: 'ZAR' },
};

const userSchema = new Schema({
  firstName: String,
  surname: String,
  userName: String,
  idNumber: Number,
  country: String,
  mobileNumber: String,
  accNumber: String,
  password: String,
  budget: 
  {
    amount: { type: Number, default: 0 },
    currency: String,
  },
  transactions: [
    {
      name: String,
      amount: Number,
      date: { type: Date, default: Date.now },
      type: { type: String, enum: ['Withdrawal', 'Payment', 'Transfer', 'Deposit'] },
    },
  ],
});

const User = mongoose.model('User', userSchema);

const employeeCredentials = {
  username: process.env.EMPLOYEE_USERNAME || 'admin',
  passwordHash: bcrypt.hashSync(process.env.EMPLOYEE_PASSWORD || 'Secure@Admin123', 10),
};

function validatePassword(password) {
  const regex = /^(?=.*[A-Z])(?=.*\W)[a-zA-Z\d\W]{8,}$/;
  return regex.test(password);
}

// Middleware to authenticate JWT from cookies
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Register endpoint for normal users
app.post('/register', async (req, res) => {
  const { firstName, surname, userName, idNumber, country, mobileNumber, accNumber, password } = req.body;

  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'Password must contain at least 8 characters, one uppercase letter, and one special character.' });
  }

  const hashedAccNumber = await bcrypt.hash(accNumber.toString(), 10);
  const hashedPassword = await bcrypt.hash(password, 10);
  const selectedCountry = countryMapping[country];

  const newUser = new User({
    firstName,
    surname,
    userName,
    idNumber,
    country,
    mobileNumber: selectedCountry.code + mobileNumber,
    accNumber: hashedAccNumber,
    password: hashedPassword,
    budget: { currency: selectedCountry.currency },
  });

  await newUser.save();
  res.status(201).json({ message: 'User registered successfully' });
});

// Login endpoint for normal users
app.post('/login', csrfProtection, async (req, res) => {
  const { userName, accNumber, password } = req.body;
  const user = await User.findOne({ userName });

  if (!user) return res.status(404).json({ error: 'User not found' });

  const isAccNumberMatch = await bcrypt.compare(accNumber.toString(), user.accNumber);
  const isPasswordMatch = await bcrypt.compare(password, user.password);

  if (!isAccNumberMatch || !isPasswordMatch) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 3600000 });
  res.json({ message: 'Login successful' });
});

// Employee login endpoint
app.post('/employee-login', csrfProtection, async (req, res) => {
  const { username, password } = req.body;

  if (username !== employeeCredentials.username || !bcrypt.compareSync(password, employeeCredentials.passwordHash)) {
    return res.status(401).json({
      error: 'Password is incorrect, please contact your superior for password details if you are an employee of this banking service',
    });
  }

  res.json({ message: 'Employee login successful' });
});

// Budget endpoint
app.post('/budget', authenticateToken, csrfProtection, async (req, res) => {
  const { amount } = req.body;
  const user = await User.findById(req.user.id);

  if (!user) return res.status(404).json({ error: 'User not found' });

  user.budget.amount = amount;
  await user.save();

  res.json({ message: 'Budget set successfully', budget: user.budget });
});

// Transactions endpoint
app.post('/transactions', authenticateToken, csrfProtection, async (req, res) => {
  const { name, amount, type } = req.body;
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (['Withdrawal', 'Payment', 'Transfer'].includes(type)) {
    user.budget.amount -= amount;
  } else if (type === 'Deposit') {
    user.budget.amount += amount;
  }

  user.transactions.push({ name, amount, type });
  await user.save();

  res.json({ message: 'Transaction added successfully', transactions: user.transactions });
});

// SWIFT Payment endpoint
app.post('/swift-payment', authenticateToken, csrfProtection, async (req, res) => {
  const { accountInfo, swiftCode, amount } = req.body;
  const user = await User.findById(req.user.id);

  if (!user) return res.status(404).json({ error: 'User not found' });

  user.transactions.push({
    name: 'SWIFT Payment',
    amount,
    type: 'Payment',
    swiftCode,
    accountInfo,
  });

  await user.save();
  res.json({ message: 'Payment processed successfully' });
});

app.use(csrfProtection);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
