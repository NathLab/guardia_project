const request = require('supertest');
const app = require('./app');

describe('Backend API Tests', () => {
  test('GET / should return 200', async () => {
    const response = await request(app).get('/');
    expect(response.status).toBe(200);
  });

  test('Server should respond with HTML', async () => {
    const response = await request(app).get('/');
    expect(response.type).toBe('text/html');
  });

  test('Response should contain "Guardia"', async () => {
    const response = await request(app).get('/');
    expect(response.text).toContain('Guardia');
  });
});
