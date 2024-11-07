// src/components/Register.js
import React, { useState } from 'react';
import { registerUser } from '../api';
import { useNavigate } from 'react-router-dom';

function Register() {
  const [form, setForm] = useState({ firstName: '', surname: '', userName: '', idNumber: '', country: '', mobileNumber: '', accNumber: '', password: '' });
  const navigate = useNavigate();

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await registerUser(form);
      alert('Registration successful! Welcome new user!');
      navigate('/');
    } catch (err) {
      alert('Registration failed');
    }
  };

  return (
    <div>
      <h2>Register</h2>
      <form onSubmit={handleSubmit}>
        <input type="text" name="firstName" onChange={handleChange} placeholder="First Name" required />
        <input type="text" name="surname" onChange={handleChange} placeholder="Surname" required />
        <input type="text" name="userName" onChange={handleChange} placeholder="Username" required />
        <input type="number" name="idNumber" onChange={handleChange} placeholder="ID Number" required />
        <select name="country" onChange={handleChange} required>
          <option value="">Select Country</option>
          <option value="Brazil">Brazil</option>
          <option value="Russia">Russia</option>
          <option value="India">India</option>
          <option value="China">China</option>
          <option value="South Africa">South Africa</option>
        </select>
        <input type="number" name="mobileNumber" onChange={handleChange} placeholder="Mobile Number" required />
        <input type="number" name="accNumber" onChange={handleChange} placeholder="Account Number" required />
        <input type="password" name="password" onChange={handleChange} placeholder="Password" required />
        <button type="submit">Register</button>
      </form>
    </div>
  );
}

export default Register;
