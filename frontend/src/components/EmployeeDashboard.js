import React, { useEffect, useState } from 'react';
import { useAuth } from './AuthContext'; // Assuming AuthContext provides user and other methods

const EmployeeDashboard = () => {
  const [paymentHistory, setPaymentHistory] = useState([]);
  const { user } = useAuth();

  useEffect(() => {
    const fetchPaymentHistory = async () => {
      try {
        const response = await fetch('/api/payment-history', {
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${document.cookie.split('token=')[1]}`, // Token assumed to be in cookies
          },
        });
        if (!response.ok) {
          throw new Error('Failed to fetch payment history');
        }
        const data = await response.json();
        setPaymentHistory(data);
      } catch (error) {
        console.error('Error fetching payment history:', error);
      }
    };

    if (user?.role === 'employee') {
      fetchPaymentHistory();
    }
  }, [user]);

  return (
    <div>
      <h2>Employee Dashboard</h2>
      <h3>Payment History</h3>
      {paymentHistory.length === 0 ? (
        <p>No payment history available.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Payment Name</th>
              <th>Amount</th>
              <th>Date</th>
            </tr>
          </thead>
          <tbody>
            {paymentHistory.map((payment, index) => (
              <tr key={index}>
                <td>{payment.userName}</td>
                <td>{payment.name}</td>
                <td>{payment.amount}</td>
                <td>{new Date(payment.date).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default EmployeeDashboard;
