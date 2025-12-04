describe('Backend API Tests', () => {
  test('Test basique - Jest fonctionne', () => {
    expect(1 + 1).toBe(2);
  });

  test('Variables environnement chargées', () => {
    expect(process.env).toBeDefined();
  });

  test('Module express disponible', () => {
    const express = require('express');
    expect(express).toBeDefined();
  });
});
