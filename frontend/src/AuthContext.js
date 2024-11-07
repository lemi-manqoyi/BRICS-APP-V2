// src/AuthContext.js
import React, { createContext, useState, useContext } from 'react';
import { loginUserAPI, loginEmployeeAPI } from './api'; // Functions are defined for API calls

const AuthContext = createContext();

export function useAuth() {
  return useContext(AuthContext);
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);

  const login = async (credentials, isEmployee) => {
    try {
      let userData;
      if (isEmployee) {
        userData = await loginEmployeeAPI(credentials);
      } else {
        userData = await loginUserAPI(credentials);
      }
      setUser(userData);
      return { success: true };
    } catch (error) {
      console.error('Login failed:', error);
      return { success: false, message: error.message };
    }
  };

  const logout = () => {
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
