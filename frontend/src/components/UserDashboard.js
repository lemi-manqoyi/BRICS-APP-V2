// src/components/UserDashboard.js
import React from 'react';

function UserDashboard({ budget, transactions }) {
  return (
    <div>
      <h2>Your Budget</h2>
      {budget ? (
        <div>
          <p>Amount: {budget.amount}</p>
          <p>Currency: {budget.currency}</p>
        </div>
      ) : (
        <p>Loading budget...</p>
      )}

      <h2>Your Transactions</h2>
      {transactions.length > 0 ? (
        <ul>
          {transactions.map((transaction) => (
            <li key={transaction._id}>
              <p>Name: {transaction.name}</p>
              <p>Amount: {transaction.amount}</p>
              <p>Type: {transaction.type}</p>
              <p>Date: {new Date(transaction.date).toLocaleString()}</p>
            </li>
          ))}
        </ul>
      ) : (
        <p>No transactions found.</p>
      )}
    </div>
  );
}

export default UserDashboard;
