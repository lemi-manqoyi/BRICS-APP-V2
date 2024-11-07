// src/components/Login.js
import React, { useState } from 'react';
import { useAuth } from '../AuthContext';
import { loginUser } from '../api';
import { useNavigate } from 'react-router-dom';

function Login() {
  const { login } = useAuth();
  const [isEmployee, setIsEmployee] = useState(false);
  const [form, setForm] = useState({ userName: '', accNumber: '', password: '' });
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  // Predefined employee credentials
  const EMPLOYEE_CREDENTIALS = {
    userName: 'admin',
    password: 'AdminSecurePassword123!', // A placeholder secure password
  };

  // Handle input changes
  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (isEmployee) {
        // Employee login logic
        if (
          form.userName === EMPLOYEE_CREDENTIALS.userName &&
          form.password === EMPLOYEE_CREDENTIALS.password
        ) {
          login({ userName: form.userName, role: 'employee' });
          navigate('/admin'); // Redirect to admin dashboard
        } else {
          setError(
            'Password is incorrect, please contact your superior for password details if you are an employee of this banking service'
          );
        }
      } else {
        // Normal user login logic
        const res = await loginUser(form); // Make API call to authenticate normal user
        login(res.data); // Save user data and JWT token
        navigate('/budget'); // Redirect to budget page
      }
    } catch (err) {
      setError(
        isEmployee
          ? 'Password is incorrect, please contact your superior for password details if you are an employee of this banking service'
          : 'Login failed. Please check your credentials.'
      );
    }
  };

  return (
    <div>
      <h2>{isEmployee ? 'Employee Login' : 'User Login'}</h2>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          name="userName"
          onChange={handleChange}
          placeholder="Username"
          value={form.userName}
          required
        />
        {!isEmployee && (
          <>
            <input
              type="text"
              name="accNumber"
              onChange={handleChange}
              placeholder="Account Number"
              value={form.accNumber}
              required
            />
            <input
              type="password"
              name="password"
              onChange={handleChange}
              placeholder="Password"
              value={form.password}
              required
            />
          </>
        )}
        {isEmployee && (
          <input
            type="password"
            name="password"
            onChange={handleChange}
            placeholder="Employee Password"
            value={form.password}
            required
          />
        )}
        <label>
          <input
            type="checkbox"
            checked={isEmployee}
            onChange={() => {
              setIsEmployee(!isEmployee);
              setForm({ userName: '', accNumber: '', password: '' }); // Reset form on toggle
              setError(null); // Clear any existing errors
            }}
          />{' '}
          Employee Login
        </label>
        {error && <p style={{ color: 'red' }}>{error}</p>}
        <button type="submit">Login</button>
      </form>
    </div>
  );
}

export default Login;
