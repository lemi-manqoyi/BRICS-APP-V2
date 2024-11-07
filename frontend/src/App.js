import React from 'react';
import { Routes, Route } from 'react-router-dom';
import UserDashboard from './components/UserDashboard';
import EmployeeDashboard from './components/EmployeeDashboard';
import Login from './components/Login';
import Register from './components/Register';
import ProtectedRoute from './components/ProtectedRoute'; // Assuming you have a protected route component

function App() {
  return (
    <div className="App">
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        {/* Protecting routes based on user role */}
        <Route path="/user-dashboard" element={<ProtectedRoute><UserDashboard /></ProtectedRoute>} />
        <Route path="/employee-dashboard" element={<ProtectedRoute><EmployeeDashboard /></ProtectedRoute>} />
      </Routes>
    </div>
  );
}

export default App;
