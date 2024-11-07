// src/api.js
export async function loginUserAPI({ username, password, accNumber }) {
  // API call to log in a regular user.
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userName: username, password, accNumber }),
  });

  if (!response.ok) {
    const { error } = await response.json();
    throw new Error(error || 'Invalid login');
  }

  return response.json(); 
}

export async function loginEmployeeAPI({ username, password }) {
  // API call to log in an employee
  const response = await fetch('/api/employee-login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    const { error } = await response.json();
    throw new Error(error || 'Invalid login');
  }

  return response.json(); // Assume response contains user data
}

// Middleware to check if the authenticated user is an employee
const authenticateEmployee = (req, res, next) => {
  const { user } = req; // Assume req.user is set after JWT authentication
  if (!user || user.role !== 'employee') {
    return res.status(403).json({ error: 'Access denied. Employee role required.' });
  }
  next();
};

// Fetch all user payment history (accessible only by employees)
app.get('/payment-history', authenticateToken, authenticateEmployee, async (req, res) => {
  try {
    const users = await User.find({});

    // Extracting payment transactions from all users
    const paymentHistory = users
      .flatMap(user => user.transactions)
      .filter(transaction => transaction.type === 'Payment')
      .map(transaction => ({
        name: transaction.name,
        amount: transaction.amount,
        date: transaction.date,
        userName: users.find(u => u.transactions.includes(transaction)).userName, // Linking transaction to a username
      }));

    res.json(paymentHistory);
  } catch (err) {
    console.error('Error fetching payment history:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
