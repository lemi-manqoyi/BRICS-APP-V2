// src/components/Transactions.js
import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import { createTransaction, getTransactions } from '../api';

function Transactions() {
  const { auth } = useAuth();
  const [transactions, setTransactions] = useState([]);
  const [transactionName, setTransactionName] = useState('');
  const [transactionAmount, setTransactionAmount] = useState('');
  const [transactionType, setTransactionType] = useState('');

  useEffect(() => {
    async function fetchTransactions() {
      try {
        const response = await getTransactions(auth.token);
        setTransactions(response.data);
      } catch (err) {
        console.error("Failed to fetch transactions:", err);
      }
    }
    fetchTransactions();
  }, [auth.token]);

  const handleAddTransaction = async () => {
    const newTransaction = {
      name: transactionName,
      amount: transactionAmount,
      type: transactionType
    };
    try {
      await createTransaction(newTransaction, auth.token);
      setTransactions([...transactions, newTransaction]);
      setTransactionName('');
      setTransactionAmount('');
      setTransactionType('');
    } catch (err) {
      console.error("Failed to add transaction:", err);
    }
  };

  return (
    <div>
      <h2>Transactions</h2>
      <input
        type="text"
        value={transactionName}
        onChange={(e) => setTransactionName(e.target.value)}
        placeholder="Transaction Name"
        required
      />
      <input
        type="number"
        value={transactionAmount}
        onChange={(e) => setTransactionAmount(e.target.value)}
        placeholder="Transaction Amount"
        required
      />
      <select
        value={transactionType}
        onChange={(e) => setTransactionType(e.target.value)}
        required
      >
        <option value="">Select Transaction Type</option>
        <option value="deposit">Deposit</option>
        <option value="withdrawal">Withdrawal</option>
        <option value="payment">Payment</option>
        <option value="transfer">Transfer</option>
      </select>
      <button onClick={handleAddTransaction}>Add Transaction</button>

      <h3>Transaction History</h3>
      <ul>
        {transactions.map((transaction, index) => (
          <li key={index}>
            {transaction.name} - {transaction.type} - {transaction.amount}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default Transactions;
