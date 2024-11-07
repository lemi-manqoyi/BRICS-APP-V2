import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { BrowserRouter } from 'react-router-dom'; // If you are using React Router
import { AuthProvider } from './AuthContext'; // Assuming you have an AuthContext file
import './index.css'; // Import any global CSS styles

// Create a root element and render the main App component
const root = ReactDOM.createRoot(document.getElementById('root'));

root.render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);
