// src/components/Budget.js
import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import { getBudget, updateBudget } from '../api';

function Budget() {
  const { auth } = useAuth();
  const [budget, setBudget] = useState(null);
  const [newBudget, setNewBudget] = useState('');
  const [currency, setCurrency] = useState('');

  useEffect(() => {
    async function fetchBudget() {
      try {
        const response = await getBudget(auth.token);
        setBudget(response.data.amount);
        setCurrency(response.data.currency);
      } catch (err) {
        console.error("Failed to fetch account data:", err);
      }
    }
    fetchBudget();
  }, [auth.token]);

  const handleUpdateBudget = async () => {
    try {
      await updateBudget({ amount: newBudget }, auth.token);
      setBudget(newBudget);
      setNewBudget('');
    } catch (err) {
      console.error("Failed to update account:", err);
    }
  };

  return (
    <div>
      <h2>Budget</h2>
      {budget !== null ? (
        <p>Current Budget: {currency} {budget}</p>
      ) : (
        <p>Loading budget...</p>
      )}
      <input
        type="number"
        value={newBudget}
        onChange={(e) => setNewBudget(e.target.value)}
        placeholder="Enter new amount"
      />
      <button onClick={handleUpdateBudget}>Update Budget</button>
    </div>
  );
}

export default Budget;
