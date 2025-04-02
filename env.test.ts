const { expect } = require('@jest/globals');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

describe('Environment Configuration', () => {
  
  // Check if .env file exists
  test('should have .env file', () => {
    const envPath = path.resolve(process.cwd(), '.env');
    const fileExists = fs.existsSync(envPath);
    expect(fileExists).toBe(true);
  });

  // Check if dotenv can load the file
  test('should load environment variables without errors', () => {
    const result = dotenv.config();
    expect(result.error).toBeUndefined();
  });

  // Check if all required environment variables are set
  test('should have all required environment variables', () => {
    // Force reload environment variables
    const result = dotenv.config();
    
    const requiredEnvVars = [
      'KEYCLOAK_URL',
      'KEYCLOAK_REALM',
      'KEYCLOAK_CLIENT_ID',
      'KEYCLOAK_CLIENT_SECRET',
      'SESSION_SECRET'
    ];
    
    for (const varName of requiredEnvVars) {
      expect(process.env[varName]).toBeDefined();
    }
  });

  // Check if environment variables don't have default values
  test('should not use default values for important variables', () => {
    // Force reload environment variables
    dotenv.config();
    
    expect(process.env.KEYCLOAK_REALM).not.toBe('your-realm');
    expect(process.env.KEYCLOAK_CLIENT_ID).not.toBe('your-client-id');
    expect(process.env.KEYCLOAK_CLIENT_SECRET).not.toBe('your-client-secret');
    expect(process.env.SESSION_SECRET).not.toBe('your-session-secret');
  });
});